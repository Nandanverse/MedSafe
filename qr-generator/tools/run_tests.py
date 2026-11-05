#!/usr/bin/env python3
"""Run the test suite without installing pytest.

**Prefer real pytest.** ``pip install -r requirements-dev.txt && pytest`` gives
better failure output, assertion rewriting, and plugins. This script exists for
two situations where that is not possible:

* an air-gapped machine — a college lab bench or an examiner's laptop with no
  package registry access, where ``pip install`` simply fails;
* a quick check that the security-critical logic still behaves, using nothing but
  the standard library plus ``cryptography``.

It implements just enough of the pytest API for this suite: fixtures,
``parametrize``, ``raises``, ``importorskip``, ``tmp_path``, and ``monkeypatch``.
It is not a general pytest replacement, and it will not silently pass a test it
cannot run — anything it does not understand is reported as an error.

Usage::

    python3 tools/run_tests.py            # everything
    python3 tools/run_tests.py crypto     # only files matching "crypto"
    python3 tools/run_tests.py -v         # list every test as it runs
"""

from __future__ import annotations

import importlib.util
import inspect
import itertools
import shutil
import sys
import tempfile
import traceback
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = ROOT / "tests"


# ── The pytest stand-in ───────────────────────────────────────────────────────


class Skipped(Exception):
    """Raised to skip a test, mirroring pytest.skip."""


class _RaisesContext:
    """Minimal ``pytest.raises``, including ``match=``."""

    def __init__(self, expected, match=None):
        self.expected = expected
        self.match = match
        self.value: BaseException | None = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        import re

        if exc_type is None:
            name = getattr(self.expected, "__name__", str(self.expected))
            raise AssertionError(f"DID NOT RAISE {name}")
        if not issubclass(exc_type, self.expected):
            return False  # propagate: wrong exception type is a failure
        if self.match is not None and not re.search(self.match, str(exc)):
            raise AssertionError(
                f"pattern {self.match!r} not found in {str(exc)!r}"
            )
        self.value = exc
        return True


class _MonkeyPatch:
    """``setattr`` with automatic undo. Enough for this suite."""

    def __init__(self) -> None:
        self._undo: list[tuple[object, str, object, bool]] = []

    def setattr(self, target, name, value):
        had = hasattr(target, name)
        old = getattr(target, name, None)
        self._undo.append((target, name, old, had))
        setattr(target, name, value)

    def delattr(self, target, name):
        had = hasattr(target, name)
        old = getattr(target, name, None)
        self._undo.append((target, name, old, had))
        if had:
            delattr(target, name)

    def undo(self):
        for target, name, old, had in reversed(self._undo):
            if had:
                setattr(target, name, old)
            else:
                try:
                    delattr(target, name)
                except AttributeError:
                    pass
        self._undo.clear()


def _fixture(func=None, **_kwargs):
    def wrap(f):
        f.__tm_fixture__ = True
        return f

    return wrap(func) if func is not None else wrap


def _parametrize(argnames, argvalues, **_kwargs):
    names = (
        [n.strip() for n in argnames.split(",")]
        if isinstance(argnames, str)
        else list(argnames)
    )

    def wrap(f):
        existing = getattr(f, "__tm_params__", [])
        f.__tm_params__ = existing + [(names, list(argvalues))]
        return f

    return wrap


def _skip(reason=""):
    raise Skipped(reason)


def _importorskip(name, **_kwargs):
    try:
        return importlib.import_module(name)
    except ImportError:
        raise Skipped(f"requires {name}") from None


class _Mark:
    """``pytest.mark`` — only ``parametrize`` is implemented."""

    parametrize = staticmethod(_parametrize)

    def __getattr__(self, name):
        # Unknown marks (skipif, xfail, ...) are not supported. Returning a no-op
        # decorator would silently change what the suite asserts, so this fails
        # loudly instead.
        def unsupported(*_a, **_k):
            raise RuntimeError(
                f"run_tests.py does not implement @pytest.mark.{name}; "
                "run the suite with real pytest"
            )

        return unsupported


def _build_pytest_stub() -> types.ModuleType:
    module = types.ModuleType("pytest")
    module.fixture = _fixture
    module.mark = _Mark()
    module.raises = lambda expected, match=None: _RaisesContext(expected, match)
    module.skip = _skip
    module.importorskip = _importorskip
    module.Skipped = Skipped
    return module


# ── Fixture resolution ────────────────────────────────────────────────────────


class FixtureResolver:
    def __init__(self, conftest: types.ModuleType) -> None:
        self.factories: dict[str, object] = {}
        for name, obj in vars(conftest).items():
            if callable(obj) and getattr(obj, "__tm_fixture__", False):
                self.factories[name] = obj
        self._cache: dict[str, object] = {}
        self._finalisers: list[object] = []

    def reset(self) -> None:
        """Function-scoped: every test gets fresh fixture instances."""
        for finalise in reversed(self._finalisers):
            finalise()
        self._finalisers.clear()
        self._cache.clear()

    def get(self, name: str):
        if name in self._cache:
            return self._cache[name]

        if name == "tmp_path":
            path = Path(tempfile.mkdtemp(prefix="truemed-test-"))
            self._finalisers.append(lambda: shutil.rmtree(path, ignore_errors=True))
            value = path
        elif name == "monkeypatch":
            patcher = _MonkeyPatch()
            self._finalisers.append(patcher.undo)
            value = patcher
        else:
            factory = self.factories.get(name)
            if factory is None:
                raise RuntimeError(f"no fixture named {name!r}")
            kwargs = {
                param: self.get(param)
                for param in inspect.signature(factory).parameters
            }
            value = factory(**kwargs)

        self._cache[name] = value
        return value


# ── Collection and execution ──────────────────────────────────────────────────


def _load(path: Path, name: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _cases(func):
    """Expand parametrize marks into concrete (id_suffix, kwargs) pairs."""
    marks = getattr(func, "__tm_params__", [])
    if not marks:
        return [("", {})]

    per_mark = []
    for names, values in marks:
        options = []
        for value in values:
            row = value if len(names) > 1 else (value,)
            options.append((dict(zip(names, row)), row))
        per_mark.append(options)

    out = []
    for combo in itertools.product(*per_mark):
        kwargs: dict[str, object] = {}
        parts = []
        for mapping, row in combo:
            kwargs.update(mapping)
            parts.append("-".join(repr(v) for v in row))
        out.append(("[" + "|".join(parts) + "]", kwargs))
    return out


def main(argv: list[str]) -> int:
    verbose = "-v" in argv
    patterns = [a for a in argv if not a.startswith("-")]

    sys.path.insert(0, str(ROOT))
    sys.modules["pytest"] = _build_pytest_stub()

    # The test modules do `from .conftest import ...`, so a real package is needed.
    package = types.ModuleType("tests")
    package.__path__ = [str(TESTS_DIR)]  # type: ignore[attr-defined]
    sys.modules["tests"] = package

    conftest = _load(TESTS_DIR / "conftest.py", "tests.conftest")
    resolver = FixtureResolver(conftest)

    files = sorted(TESTS_DIR.glob("test_*.py"))
    if patterns:
        files = [f for f in files if any(p in f.name for p in patterns)]
    if not files:
        print(f"no test files matched {patterns}")
        return 1

    passed = failed = skipped = 0
    failures: list[tuple[str, str]] = []

    for path in files:
        module = _load(path, f"tests.{path.stem}")
        print(f"\n{path.name}")

        classes = [
            (name, obj)
            for name, obj in vars(module).items()
            if inspect.isclass(obj) and name.startswith("Test")
        ]
        loose = [
            (name, obj)
            for name, obj in vars(module).items()
            if inspect.isfunction(obj) and name.startswith("test_")
        ]

        groups: list[tuple[str, object, list[tuple[str, object]]]] = []
        for cls_name, cls in classes:
            methods = [
                (n, getattr(cls, n))
                for n in vars(cls)
                if n.startswith("test_") and callable(getattr(cls, n))
            ]
            groups.append((cls_name, cls, methods))
        if loose:
            groups.append(("", None, loose))

        for cls_name, cls, methods in groups:
            if cls_name:
                print(f"  {cls_name}")
            for method_name, func in methods:
                for suffix, params in _cases(func):
                    label = f"{cls_name}::{method_name}{suffix}" if cls_name else \
                            f"{method_name}{suffix}"
                    resolver.reset()
                    try:
                        signature = inspect.signature(func)
                        kwargs = dict(params)
                        for param in signature.parameters:
                            if param in ("self", "cls") or param in kwargs:
                                continue
                            kwargs[param] = resolver.get(param)
                        if cls is not None:
                            func(cls(), **kwargs)
                        else:
                            func(**kwargs)
                    except Skipped as exc:
                        skipped += 1
                        if verbose:
                            print(f"    - {label}  SKIP ({exc})")
                    except Exception:  # noqa: BLE001 - a failure is a failure
                        failed += 1
                        failures.append((label, traceback.format_exc()))
                        print(f"    X {label}")
                    else:
                        passed += 1
                        if verbose:
                            print(f"    . {label}")
                    finally:
                        resolver.reset()

    print("\n" + "=" * 72)
    if failures:
        for label, trace in failures:
            print(f"\nFAILED {label}\n{'-' * 72}\n{trace}")
        print("=" * 72)
    print(f"passed {passed}   failed {failed}   skipped {skipped}")
    if skipped and not verbose:
        print("(re-run with -v to see which tests were skipped and why)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
