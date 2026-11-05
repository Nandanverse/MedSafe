"""TrueMed QR generator — command-line interface.

Seven subcommands::

    keygen     create a signing key set and a root-signed trust bundle
    generate   sign one payload and render its QR
    batch      sign many payloads from a JSON file
    demo       generate the built-in sample catalogue
    verify     verify a wire string or a PNG, offline
    inspect    decode a wire string without verifying it
    selftest   end-to-end round trip in a temporary directory

Two design points that are easy to get wrong, and that this module exists partly
to get right:

**Signing keys are loaded, never generated.** A ``generate`` that mints a fresh
key pair per invocation produces QR codes nothing can ever verify — the key is
gone when the process exits. So every signing path here requires a key set on
disk, produced once by ``keygen``, and fails with an actionable message if it is
absent.

**Key passwords never arrive on the command line.** ``argv`` is visible to every
process on the machine via ``ps`` and lands in shell history. Passwords come from
a file, an environment variable, or an interactive prompt.

Output is deliberately plain ASCII. A tick or cross character raises
``UnicodeEncodeError`` the moment someone on Windows redirects output to a file,
because a redirected stream uses the locale encoding (cp1252) rather than the
console's UTF-8 — a crash in a logging path is a poor trade for decoration.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Sequence

from . import __version__
from .codec import decode as decode_wire
from .codec import encode as encode_wire
from .crypto import (
    TrustBundle,
    TrustedKey,
    fingerprint,
    generate_private_key,
    load_private_key,
    load_public_key,
    private_key_to_pem,
    public_key_to_pem,
)
from .demo_data import MANUFACTURERS, demo_medicines, notes_for
from .errors import KeyStoreError, PayloadError, TrueMedError
from .generator import build_wire
from .generator import generate as generate_qr
from .payload import (
    MAX_PAYLOAD_BYTES,
    QR_MAX_BYTES_ECC_H,
    TYPE_MEDICINE,
    TYPE_VACCINE,
    MedicineData,
    make_product_id,
    parse_iso_date,
)
from .verifier import (
    SEVERITY_CRITICAL,
    VerificationResult,
    decode_qr_image,
    merge_online_evidence,
    verify_wire,
)

# ── Exit codes ────────────────────────────────────────────────────────────────
#
# Distinct codes for "the tool broke" and "the tool worked and the medicine is
# fake" matter to anything that shells out to this: a CI job or the blockchain
# smoke test needs to tell a missing key file apart from a detected counterfeit.
# argparse owns 2 for usage errors, so that value is left alone.

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_VERDICT_WARN = 3
EXIT_VERDICT_CRITICAL = 4

# ── Key set layout ────────────────────────────────────────────────────────────

KEYSET_VERSION = 1
KEYSET_FILENAME = "keyset.json"
BUNDLE_FILENAME = "trust-bundle.json"
ROOT_PRIVATE_FILENAME = "root.key"
ROOT_PUBLIC_FILENAME = "root.pub"
SIGNERS_DIRNAME = "signers"
MANIFEST_FILENAME = "manifest.json"

DEFAULT_KEYS_DIR = "keys"
DEFAULT_PASSWORD_ENV = "TRUEMED_KEY_PASSWORD"

_NON_FILENAME = re.compile(r"[^A-Za-z0-9]+")


# ── Small helpers ─────────────────────────────────────────────────────────────


def _out(line: str = "") -> None:
    print(line)


def _err(line: str) -> None:
    """Write a warning or error to stderr, preserving order relative to stdout.

    Without the flush, redirecting output to a file block-buffers stdout while
    stderr stays unbuffered, so warnings surface *above* the lines they refer to.
    In a demo log that reads as though the run failed before it started.
    """
    sys.stdout.flush()
    print(line, file=sys.stderr)
    sys.stderr.flush()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slug(text: str) -> str:
    """Filesystem-safe form of a licence number.

    ``MH/25D/2019/187`` contains path separators, so it cannot be a filename on
    any platform. Collapsing runs of non-alphanumerics to a hyphen is reversible
    enough for a human and the authoritative mapping lives in ``keyset.json``
    anyway.
    """
    return _NON_FILENAME.sub("-", text).strip("-")


def _fmt_days(days: int) -> str:
    if days < 0:
        n = -days
        return f"{n} day{'s' if n != 1 else ''} ago"
    if days == 0:
        return "today"
    return f"in {days} day{'s' if days != 1 else ''}"


def _write_secret(path: Path, data: bytes) -> None:
    """Write private key material with owner-only permissions from creation.

    ``open()`` then ``chmod()`` leaves a window in which the file exists
    world-readable, and on a shared college lab machine that window is enough.
    ``os.open`` with an explicit mode closes it. The mode is advisory on Windows,
    which is noted in the README rather than papered over here.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _read_json(path: Path, what: str) -> Any:
    if not path.is_file():
        raise TrueMedError(f"no such {what}: {path}", code="FILE_NOT_FOUND")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TrueMedError(
            f"{path} is not valid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})",
            code="FILE_MALFORMED",
        ) from exc
    except UnicodeDecodeError as exc:
        raise TrueMedError(f"{path} is not valid UTF-8", code="FILE_MALFORMED") from exc


# ── Password resolution ───────────────────────────────────────────────────────


def _password_from_sources(args: argparse.Namespace) -> str | None:
    """Resolve a key password from a file or an environment variable.

    Order is file, then environment. Returns ``None`` when neither is set, which
    callers treat as "the key is probably unencrypted, and if it is not we may
    prompt".
    """
    path_arg = getattr(args, "key_password_file", None)
    if path_arg:
        path = Path(path_arg)
        if not path.is_file():
            raise KeyStoreError(f"--key-password-file {path} does not exist")
        # Strip only the trailing newline an editor adds. Leading and internal
        # whitespace can legitimately be part of a generated password.
        password = path.read_text(encoding="utf-8").rstrip("\r\n")
        if not password:
            raise KeyStoreError(f"--key-password-file {path} is empty")
        return password

    env_name = getattr(args, "key_password_env", None) or DEFAULT_PASSWORD_ENV
    password = os.environ.get(env_name)
    if password:
        return password
    return None


def _looks_encrypted(pem: bytes) -> bool:
    return b"ENCRYPTED PRIVATE KEY" in pem


def _load_signing_key(path: Path, args: argparse.Namespace):
    """Load a private key, prompting for a password only if one is needed."""
    if not path.is_file():
        raise KeyStoreError(
            f"signing key {path} not found. Create a key set first:\n"
            f"    python main.py keygen --out {DEFAULT_KEYS_DIR}/"
        )
    pem = path.read_bytes()
    password = _password_from_sources(args)

    if password is None and _looks_encrypted(pem):
        if not sys.stdin.isatty():
            raise KeyStoreError(
                f"{path.name} is password-protected and no password source is set. "
                f"Export {DEFAULT_PASSWORD_ENV} or pass --key-password-file. "
                "Passwords are not accepted as command-line arguments because argv "
                "is world-readable via ps."
            )
        password = getpass.getpass(f"Password for {path.name}: ")

    return load_private_key(pem, password)


def _password_for_new_keys(args: argparse.Namespace) -> str | None:
    """Resolve the password to encrypt freshly generated keys with."""
    if not getattr(args, "encrypt", False):
        return None

    password = _password_from_sources(args)
    if password is not None:
        return password

    if not sys.stdin.isatty():
        raise KeyStoreError(
            "--encrypt needs a password, and stdin is not a terminal so there is "
            f"nothing to prompt. Export {DEFAULT_PASSWORD_ENV} or pass "
            "--key-password-file."
        )

    first = getpass.getpass("Password for the new private keys: ")
    if not first:
        raise KeyStoreError("empty password; either supply one or drop --encrypt")
    second = getpass.getpass("Confirm: ")
    if first != second:
        raise KeyStoreError("passwords do not match")
    return first


# ── Key set ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Signer:
    """One manufacturer signing identity as recorded in ``keyset.json``."""

    mfg_licence_no: str
    manufacturer: str
    private_key_file: str
    public_key_file: str
    fingerprint: str
    valid_from: str
    valid_until: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "mfg_licence_no": self.mfg_licence_no,
            "manufacturer": self.manufacturer,
            "private_key_file": self.private_key_file,
            "public_key_file": self.public_key_file,
            "fingerprint": self.fingerprint,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> "Signer":
        if not isinstance(raw, dict):
            raise KeyStoreError(
                f"each keyset signer must be an object, got {type(raw).__name__}"
            )
        try:
            return cls(
                mfg_licence_no=raw["mfg_licence_no"],
                manufacturer=raw["manufacturer"],
                private_key_file=raw["private_key_file"],
                public_key_file=raw["public_key_file"],
                fingerprint=raw["fingerprint"],
                valid_from=raw["valid_from"],
                valid_until=raw["valid_until"],
            )
        except KeyError as exc:
            raise KeyStoreError(
                f"keyset signer entry is missing field {exc.args[0]!r}"
            ) from exc


class KeySet:
    """The signing keys on disk, indexed by manufacturing licence number.

    One key per licence, which mirrors reality: a licence is issued to a specific
    manufacturing site, and the trust bundle maps licence to public key. Sharing
    one key across licences would work cryptographically and would misrepresent
    the trust model in a viva.
    """

    def __init__(self, directory: Path, signers: Sequence[Signer], created_at: str) -> None:
        self.directory = directory
        self.signers = list(signers)
        self.created_at = created_at
        self._by_licence = {s.mfg_licence_no: s for s in self.signers}

    @classmethod
    def load(cls, directory: str | Path) -> "KeySet":
        path = Path(directory) / KEYSET_FILENAME
        if not path.is_file():
            raise KeyStoreError(
                f"no {KEYSET_FILENAME} in {directory}. Create a key set first:\n"
                f"    python main.py keygen --out {directory}"
            )
        raw = _read_json(path, "key set index")
        if not isinstance(raw, dict):
            raise KeyStoreError(f"{path} must contain a JSON object")
        if raw.get("version") != KEYSET_VERSION:
            raise KeyStoreError(
                f"{path} is version {raw.get('version')!r}; this build writes and "
                f"reads version {KEYSET_VERSION}"
            )
        entries = raw.get("signers")
        if not isinstance(entries, list) or not entries:
            raise KeyStoreError(f"{path} lists no signers")
        return cls(
            Path(directory),
            [Signer.from_dict(e) for e in entries],
            raw.get("created_at", "unknown"),
        )

    def to_json(self) -> str:
        return json.dumps(
            {
                "version": KEYSET_VERSION,
                "created_at": self.created_at,
                "root_public_key_file": ROOT_PUBLIC_FILENAME,
                "signers": [s.to_dict() for s in self.signers],
            },
            indent=2,
            ensure_ascii=False,
        )

    def licences(self) -> list[str]:
        return [s.mfg_licence_no for s in self.signers]

    def signer_for(self, mfg_licence_no: str) -> Signer:
        signer = self._by_licence.get(mfg_licence_no)
        if signer is None:
            raise KeyStoreError(
                f"no signing key in {self.directory} for manufacturing licence "
                f"{mfg_licence_no!r}. Known licences: {', '.join(self.licences())}. "
                "Add one with:\n"
                f"    python main.py keygen --out {self.directory} --licence "
                f"{mfg_licence_no} --manufacturer '<name>' --add"
            )
        return signer

    def private_key_for(self, mfg_licence_no: str, args: argparse.Namespace):
        signer = self.signer_for(mfg_licence_no)
        return _load_signing_key(self.directory / signer.private_key_file, args)


def _load_bundle(args: argparse.Namespace) -> TrustBundle:
    """Load the trust bundle, verifying its root signature unless told not to."""
    keys_dir = Path(getattr(args, "keys", None) or DEFAULT_KEYS_DIR)
    bundle_path = Path(args.bundle) if getattr(args, "bundle", None) else keys_dir / BUNDLE_FILENAME

    if not bundle_path.is_file():
        raise KeyStoreError(
            f"no trust bundle at {bundle_path}. Create one:\n"
            f"    python main.py keygen --out {keys_dir}/"
        )

    allow_unsigned = bool(getattr(args, "allow_unsigned_bundle", False))
    root_public_key = None

    if not allow_unsigned:
        root_arg = getattr(args, "root_pub", None)
        root_path = Path(root_arg) if root_arg else bundle_path.parent / ROOT_PUBLIC_FILENAME
        if not root_path.is_file():
            raise KeyStoreError(
                f"no root public key at {root_path}, so the trust bundle's signature "
                "cannot be checked. An unverified bundle is worthless — anyone who can "
                "serve it can insert their own signing key. Pass --root-pub, or "
                "--allow-unsigned-bundle for local development only."
            )
        root_public_key = load_public_key(root_path.read_bytes())
    else:
        _err(
            "warning: --allow-unsigned-bundle skips the root signature check. Any "
            "tampered bundle will be accepted. Never use this in a build you hand to "
            "a patient."
        )

    return TrustBundle.from_json(
        bundle_path.read_text(encoding="utf-8"),
        root_public_key=root_public_key,
        require_signature=not allow_unsigned,
    )


# ── keygen ────────────────────────────────────────────────────────────────────


def cmd_keygen(args: argparse.Namespace) -> int:
    out_dir = Path(args.out)
    signers_dir = out_dir / SIGNERS_DIRNAME
    keyset_path = out_dir / KEYSET_FILENAME
    root_private_path = out_dir / ROOT_PRIVATE_FILENAME
    root_public_path = out_dir / ROOT_PUBLIC_FILENAME

    if args.licence and not args.manufacturer:
        _err("--licence requires --manufacturer")
        return EXIT_USAGE
    if args.add and not args.licence:
        _err("--add requires --licence and --manufacturer")
        return EXIT_USAGE

    existing: KeySet | None = None
    if keyset_path.is_file():
        if args.add:
            existing = KeySet.load(out_dir)
        elif not args.force:
            # Overwriting a manufacturer signing key silently invalidates every QR
            # ever printed under it: the trust bundle would advertise a new public
            # key and every strip already on a shelf would verify as counterfeit.
            # That is not a mistake to allow by default.
            _err(
                f"{keyset_path} already exists. Overwriting it replaces the signing "
                "keys, and every QR already printed under the old keys would then "
                "verify as COUNTERFEIT.\n"
                "  --add    to append a new signer, keeping the existing ones\n"
                "  --force  to discard and regenerate everything"
            )
            return EXIT_ERROR

    password = _password_for_new_keys(args)

    # Verification checks the signing key's validity window against the *date of
    # the scan*, not the medicine's manufacture date. Anchoring valid_from to
    # today would therefore reject two entirely legitimate cases: a strip
    # manufactured before the key was minted, and a reproducible demo pinned to a
    # past date with --today. So the window opens well in the past — a licence
    # issued years ago is also simply more realistic than one whose validity began
    # the instant keygen ran. valid_until is anchored forward from today, because
    # --valid-years is really "how long codes minted now keep verifying".
    today = date.today()
    valid_from = date(today.year - 5, 1, 1)
    valid_until = today + timedelta(days=365 * args.valid_years)

    # Root key. Regenerated on --force, reused on --add, because rotating the root
    # invalidates every bundle every app has pinned.
    if args.add and root_private_path.is_file():
        root_private = _load_signing_key(root_private_path, args)
    else:
        root_private = generate_private_key()
        _write_secret(root_private_path, private_key_to_pem(root_private, password))
        _write_text(root_public_path, public_key_to_pem(root_private.public_key()).decode())

    requested: list[tuple[str, str]]
    if args.licence:
        requested = [(args.licence, args.manufacturer)]
    else:
        # The default set covers every manufacturer in the demo catalogue, so
        # `keygen` followed by `demo` works with no further arguments.
        requested = [(m.licence_no, m.name) for m in MANUFACTURERS]

    signers: list[Signer] = list(existing.signers) if existing else []
    known = {s.mfg_licence_no for s in signers}
    created: list[Signer] = []

    for licence, manufacturer in requested:
        if licence in known:
            _err(f"warning: licence {licence} already has a key; leaving it untouched")
            continue
        private = generate_private_key()
        public = private.public_key()
        slug = _slug(licence)
        private_rel = f"{SIGNERS_DIRNAME}/{slug}.key"
        public_rel = f"{SIGNERS_DIRNAME}/{slug}.pub"
        _write_secret(signers_dir / f"{slug}.key", private_key_to_pem(private, password))
        _write_text(signers_dir / f"{slug}.pub", public_key_to_pem(public).decode())
        signer = Signer(
            mfg_licence_no=licence,
            manufacturer=manufacturer,
            private_key_file=private_rel,
            public_key_file=public_rel,
            fingerprint=fingerprint(public),
            valid_from=valid_from.isoformat(),
            valid_until=valid_until.isoformat(),
        )
        signers.append(signer)
        created.append(signer)
        known.add(licence)

    if not signers:
        _err("no signers to write")
        return EXIT_ERROR

    keyset = KeySet(out_dir, signers, _now_iso())
    _write_text(keyset_path, keyset.to_json())

    bundle = TrustBundle(
        [
            TrustedKey(
                mfg_licence_no=s.mfg_licence_no,
                manufacturer=s.manufacturer,
                public_key_pem=(out_dir / s.public_key_file).read_text(encoding="utf-8"),
                fingerprint=s.fingerprint,
                valid_from=s.valid_from,
                valid_until=s.valid_until,
            )
            for s in signers
        ]
    )
    _write_text(out_dir / BUNDLE_FILENAME, bundle.to_json(root_private_key=root_private))

    _out(f"Key set written to {out_dir}")
    _out()
    _out(f"  root private key   {ROOT_PRIVATE_FILENAME}")
    _out(f"  root public key    {ROOT_PUBLIC_FILENAME}   <- pin this in the mobile app")
    _out(f"  trust bundle       {BUNDLE_FILENAME}   ({len(signers)} signer(s), root-signed)")
    _out(f"  index              {KEYSET_FILENAME}")
    _out()
    _out(f"  root fingerprint   {fingerprint(root_private.public_key())}")
    _out()
    label = "Added" if args.add else "Signers"
    _out(f"{label}:")
    for signer in (created if args.add else signers):
        _out(f"  {signer.fingerprint}  {signer.mfg_licence_no:<20} {signer.manufacturer}")
    _out()
    _out(f"  valid {valid_from.isoformat()} to {valid_until.isoformat()}")
    _out()

    if password is None:
        _err(
            "warning: private keys were written unencrypted. Anyone who reads "
            f"{out_dir}/ can mint QR codes that verify as genuine. For anything "
            "beyond a local demo, regenerate with --encrypt and keep the password "
            "out of the repository."
        )
    _out("Next:  python main.py demo --count 5 --out out/")
    return EXIT_OK


# ── generate ──────────────────────────────────────────────────────────────────


def _medicine_from_args(args: argparse.Namespace) -> MedicineData:
    mfg = parse_iso_date(args.mfg_date, "--mfg-date")
    parse_iso_date(args.expiry_date, "--expiry-date")

    product_id = args.product_id or make_product_id(
        args.generic_name, args.brand_name, mfg.year, args.serial
    )
    return MedicineData(
        product_id=product_id,
        generic_name=args.generic_name,
        brand_name=args.brand_name,
        manufacturer=args.manufacturer,
        mfg_licence_no=args.mfg_licence_no,
        batch_no=args.batch_no,
        mfg_date=args.mfg_date,
        expiry_date=args.expiry_date,
        quantity=args.quantity,
        # Repeatable --excipient rather than one comma-separated string, because
        # excipient names contain commas ("Iron Oxide, Red") and a joined string
        # would be ambiguous. The data contract requires a JSON array for exactly
        # this reason.
        excipients=list(args.excipient or []),
        med_type=args.type,
    )


def _emit_generated(results: list[dict[str, Any]], args: argparse.Namespace) -> None:
    if getattr(args, "json", False):
        _out(json.dumps(results, indent=2, ensure_ascii=False))
        return
    for item in results:
        _out(f"  {item['product_id']}")
        if item.get("png_path"):
            _out(f"    png      {item['png_path']}  (QR version {item['qr_version']}, "
                 f"{item['modules_per_side']}x{item['modules_per_side']} modules)")
        _out(f"    wire     {item['wire_bytes']} bytes "
             f"({item['wire_bytes'] * 100 // QR_MAX_BYTES_ECC_H}% of the "
             f"{QR_MAX_BYTES_ECC_H}-byte level-H ceiling)")
        for warning in item.get("warnings", []):
            _err(f"    warning  {warning}")


def _generate_one(
    medicine: MedicineData, private_key: Any, args: argparse.Namespace
) -> dict[str, Any]:
    out_dir = None if args.no_png else Path(args.out)
    result = generate_qr(
        medicine,
        private_key,
        out_dir,
        scale=args.scale,
        border=args.border,
        with_caption=not args.no_caption,
    )
    payload = result.as_dict()
    payload["data"] = medicine.to_dict()
    return payload


def cmd_generate(args: argparse.Namespace) -> int:
    medicine = _medicine_from_args(args)
    if args.key:
        private_key = _load_signing_key(Path(args.key), args)
    else:
        private_key = KeySet.load(args.keys).private_key_for(medicine.mfg_licence_no, args)

    result = _generate_one(medicine, private_key, args)
    if not args.json:
        _out(f"Generated 1 QR code for licence {medicine.mfg_licence_no}")
        _out()
    _emit_generated([result], args)
    return EXIT_OK


# ── batch ─────────────────────────────────────────────────────────────────────


def _medicines_from_json(
    raw: Any, source: Path
) -> tuple[list[MedicineData], list[str]]:
    """Parse a batch input file into payloads, plus a list of per-record failures.

    Accepts either a bare array or ``{"medicines": [...], "vaccines": [...]}``. The
    grouped form is what a human naturally writes when sampling both product
    types, and rejecting it over a cosmetic difference would be unhelpful.

    A bad record is reported and skipped rather than aborting the run: on a file of
    two hundred units, one typo should not throw away the other hundred and
    ninety-nine signatures. A malformed *file* is still fatal — there is nothing to
    salvage.
    """
    if isinstance(raw, list):
        entries = raw
    elif isinstance(raw, dict):
        entries = []
        for group in ("medicines", "vaccines", "items"):
            value = raw.get(group)
            if value is None:
                continue
            if not isinstance(value, list):
                raise TrueMedError(
                    f"{source}: key {group!r} must be an array",
                    code="FILE_MALFORMED",
                )
            entries.extend(value)
        if not entries:
            raise TrueMedError(
                f"{source}: expected a JSON array, or an object with a 'medicines', "
                "'vaccines' or 'items' array",
                code="FILE_MALFORMED",
            )
    else:
        raise TrueMedError(
            f"{source}: expected a JSON array or object, got {type(raw).__name__}",
            code="FILE_MALFORMED",
        )

    medicines: list[MedicineData] = []
    failures: list[str] = []

    for index, entry in enumerate(entries, start=1):
        try:
            medicines.append(MedicineData.from_dict(entry))
        except TrueMedError as exc:
            # Name the offending record. "brand_name must not be empty" is useless
            # when the input file holds two hundred of them.
            identifier = ""
            if isinstance(entry, dict):
                identifier = str(entry.get("product_id") or entry.get("batch_no") or "")
            where = f"entry {index}" + (f" ({identifier})" if identifier else "")
            failures.append(f"{where}: {exc.message}")

    if not medicines and failures:
        raise PayloadError(
            f"{source}: every one of the {len(failures)} records is invalid. First: "
            f"{failures[0]}"
        )
    return medicines, failures


def _write_manifest(
    args: argparse.Namespace,
    results: list[dict[str, Any]],
    notes: list[str] | None = None,
) -> Path | None:
    """Record what was generated, for the other components to consume.

    The blockchain smoke test and the API seed script both need the same
    ``product_id`` values and wire strings this run produced. Writing them once
    here is what keeps the three components describing the same medicines.

    Written even under ``--no-png``: the manifest carries the wire strings, and
    tying the other components' seed data to whether Pillow happens to be
    installed would be an absurd coupling.
    """
    if not results or getattr(args, "no_manifest", False):
        return None

    out_dir = Path(args.out)
    manifest = {
        "contract_version": 1,
        "generated_at": _now_iso(),
        "count": len(results),
        "items": results,
    }
    if notes:
        manifest["notes"] = notes
    path = out_dir / MANIFEST_FILENAME
    _write_text(path, json.dumps(manifest, indent=2, ensure_ascii=False))
    return path


def cmd_batch(args: argparse.Namespace) -> int:
    source = Path(args.input)
    medicines, failures = _medicines_from_json(
        _read_json(source, "batch input file"), source
    )
    attempted = len(medicines) + len(failures)

    keyset: KeySet | None = None
    single_key = None
    if args.key:
        single_key = _load_signing_key(Path(args.key), args)
    else:
        keyset = KeySet.load(args.keys)

    results: list[dict[str, Any]] = []
    cache: dict[str, Any] = {}

    for medicine in medicines:
        try:
            if single_key is not None:
                private_key = single_key
            else:
                assert keyset is not None
                if medicine.mfg_licence_no not in cache:
                    cache[medicine.mfg_licence_no] = keyset.private_key_for(
                        medicine.mfg_licence_no, args
                    )
                private_key = cache[medicine.mfg_licence_no]
            results.append(_generate_one(medicine, private_key, args))
        except TrueMedError as exc:
            # One bad record must not discard the work already done on a long run,
            # so failures are collected and reported at the end.
            failures.append(f"{medicine.product_id}: {exc.message}")

    manifest = _write_manifest(args, results)

    if args.json:
        _out(json.dumps(
            {"generated": results, "failed": failures,
             "manifest": str(manifest) if manifest else None},
            indent=2, ensure_ascii=False,
        ))
    else:
        _out(f"Generated {len(results)} of {attempted} from {source}")
        _out()
        _emit_generated(results, args)
        if manifest:
            _out()
            _out(f"  manifest {manifest}")
        if failures:
            _err("")
            _err(f"{len(failures)} failed:")
            for line in failures:
                _err(f"  {line}")

    return EXIT_ERROR if failures else EXIT_OK


# ── demo ──────────────────────────────────────────────────────────────────────


def cmd_demo(args: argparse.Namespace) -> int:
    today = parse_iso_date(args.today, "--today") if args.today else None
    try:
        medicines = demo_medicines(args.count, today)
    except ValueError as exc:
        _err(str(exc))
        return EXIT_USAGE

    keyset = KeySet.load(args.keys)
    cache: dict[str, Any] = {}
    results: list[dict[str, Any]] = []

    for medicine in medicines:
        if medicine.mfg_licence_no not in cache:
            cache[medicine.mfg_licence_no] = keyset.private_key_for(
                medicine.mfg_licence_no, args
            )
        results.append(_generate_one(medicine, cache[medicine.mfg_licence_no], args))

    notes = notes_for(args.count)
    manifest = _write_manifest(args, results, notes)

    if args.json:
        _out(json.dumps(
            {"generated": results, "notes": notes,
             "manifest": str(manifest) if manifest else None},
            indent=2, ensure_ascii=False,
        ))
        return EXIT_OK

    _out(f"Generated {len(results)} demo codes")
    _out()
    _emit_generated(results, args)
    _out()
    _out("What each one demonstrates:")
    for note in notes:
        _out(f"  {note}")
    if manifest:
        _out()
        _out(f"  manifest {manifest}")
    _out()
    _out("Verify one:")
    if results and results[0].get("png_path"):
        _out(f"  python main.py verify --image {results[0]['png_path']}")
    elif manifest:
        _out(f"  python -c \"import json;print(json.load(open(r'{manifest}'))"
             "['items'][0]['wire'])\" | python main.py verify --stdin")
    else:
        _out("  python main.py demo --count 1 --json   # then verify --wire <string>")
    return EXIT_OK


# ── verify ────────────────────────────────────────────────────────────────────


def _chain_evidence(path: Path) -> dict[str, Any]:
    """Validate a chain-evidence file for ``verify --chain-json``.

    Exists so all six verdicts can be demonstrated without a running network.
    The shape mirrors what the API passes to :func:`merge_online_evidence`.
    """
    raw = _read_json(path, "chain evidence file")
    if not isinstance(raw, dict):
        raise TrueMedError(
            f"{path}: expected a JSON object", code="FILE_MALFORMED"
        )
    if "on_chain" not in raw or not isinstance(raw["on_chain"], bool):
        raise TrueMedError(
            f"{path}: 'on_chain' is required and must be true or false. Without it "
            "there is no way to tell 'absent from the ledger' from 'not asked'.",
            code="FILE_MALFORMED",
        )

    evidence: dict[str, Any] = {"on_chain": raw["on_chain"]}
    if raw.get("status") is not None:
        if not isinstance(raw["status"], str):
            raise TrueMedError(f"{path}: 'status' must be a string", code="FILE_MALFORMED")
        evidence["status"] = raw["status"]
    if raw.get("cold_chain_breached") is not None:
        if not isinstance(raw["cold_chain_breached"], bool):
            raise TrueMedError(
                f"{path}: 'cold_chain_breached' must be true or false",
                code="FILE_MALFORMED",
            )
        evidence["cold_chain_breached"] = raw["cold_chain_breached"]
    if raw.get("temperature_readings") is not None:
        readings = raw["temperature_readings"]
        if not isinstance(readings, list):
            raise TrueMedError(
                f"{path}: 'temperature_readings' must be an array",
                code="FILE_MALFORMED",
            )
        evidence["temperature_readings"] = readings
    for field_name in ("scan_count", "distinct_districts"):
        value = raw.get(field_name)
        if value is None:
            continue
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise TrueMedError(
                f"{path}: {field_name!r} must be a non-negative integer",
                code="FILE_MALFORMED",
            )
        evidence[field_name] = value
    return evidence


def _read_wire(args: argparse.Namespace) -> str:
    """Obtain the wire string from --wire, --image, or stdin.

    The emptiness checks are load-bearing. ``--wire "$W"`` with ``W`` unset passes
    an empty string, and testing truthiness here would fall through to reading
    stdin — which, with no pipe attached, hangs the process forever with no
    output. A shell typo should produce a message, not a mystery.
    """
    if args.wire is not None:
        if not args.wire.strip():
            raise TrueMedError(
                "--wire is empty. If it came from a shell variable, that variable is "
                "unset.",
                code="QR_MALFORMED",
            )
        return args.wire.strip()

    if args.image is not None:
        if not args.image.strip():
            raise TrueMedError("--image is empty", code="QR_MALFORMED")
        return decode_qr_image(args.image)

    if sys.stdin.isatty():
        # Reading from a terminal would look identical to a hang.
        raise TrueMedError(
            "--stdin was given but stdin is a terminal, so there is nothing to read. "
            "Pipe a wire string in, or use --wire.",
            code="QR_MALFORMED",
        )
    data = sys.stdin.read().strip()
    if not data:
        raise TrueMedError("nothing arrived on stdin", code="QR_MALFORMED")
    # A file of wire strings piped in should verify the first one rather than
    # failing on the newline.
    return data.splitlines()[0].strip()


def _print_verification(result: VerificationResult, today: date) -> None:
    _out(result.summary_line())
    medicine = result.medicine
    if medicine is not None:
        data = result.data or {}
        _out(f"  product_id    {medicine.product_id}")
        _out(f"  generic       {medicine.generic_name}")
        _out(f"  brand         {medicine.brand_name}")
        _out(f"  manufacturer  {medicine.manufacturer}")
        _out(f"  licence       {medicine.mfg_licence_no}")
        _out(f"  batch         {medicine.batch_no}")
        _out(f"  type          {medicine.med_type}")
        _out(
            f"  expiry        {medicine.expiry_date} "
            f"({_fmt_days(medicine.days_to_expiry(today))})"
        )
        if medicine.excipients:
            _out(f"  excipients    {', '.join(medicine.excipients)}")
        key_fp = data.get("signing_key_fingerprint")
        if key_fp:
            _out(f"  signing key   {key_fp}")
        if data.get("status") is not None:
            _out(f"  chain status  {data['status']}")
    _out("  checks        " + "  ".join(
        f"{name}={state}" for name, state in result.checks.items()
    ))
    if result.error:
        _out(f"  reason        {result.error}")
    for warning in result.warnings:
        _out(f"  note          {warning}")


def _verdict_exit(result: VerificationResult) -> int:
    """Map a verdict to a process exit code.

    ``SIGNATURE_VALID_OFFLINE`` exits 0 even though the app paints it amber. The
    two audiences differ: a patient needs to know the check was partial, while a
    script running under ``set -e`` must not treat a correctly signed code as a
    failure just because the network was unavailable.
    """
    if result.valid:
        return EXIT_OK
    if result.severity == SEVERITY_CRITICAL:
        return EXIT_VERDICT_CRITICAL
    return EXIT_VERDICT_WARN


def cmd_verify(args: argparse.Namespace) -> int:
    today = parse_iso_date(args.today, "--today") if args.today else date.today()
    bundle = _load_bundle(args)
    wire = _read_wire(args)

    result = verify_wire(wire, bundle, today=today)

    if args.chain_json:
        result = merge_online_evidence(
            result, today=today, **_chain_evidence(Path(args.chain_json))
        )

    if args.json:
        _out(json.dumps(result.as_dict(), indent=2, ensure_ascii=False))
    else:
        _print_verification(result, today)
    return _verdict_exit(result)


# ── inspect ───────────────────────────────────────────────────────────────────


def cmd_inspect(args: argparse.Namespace) -> int:
    wire = _read_wire(args)
    decoded = decode_wire(wire)
    payload_text = decoded.payload_bytes.decode("utf-8", errors="replace")

    try:
        parsed: Any = json.loads(payload_text)
    except json.JSONDecodeError:
        parsed = None

    wire_bytes = len(wire.encode("ascii", errors="replace"))
    payload_bytes = len(decoded.payload_bytes)

    if args.json:
        _out(json.dumps(
            {
                "prefix": decoded.prefix,
                "wire_bytes": wire_bytes,
                "payload_bytes": payload_bytes,
                "signature_bytes": len(decoded.signature),
                "signature_hex": decoded.signature.hex(),
                "payload": parsed,
                "signature_checked": False,
            },
            indent=2, ensure_ascii=False,
        ))
        return EXIT_OK

    _out(f"prefix            {decoded.prefix}")
    _out(f"wire              {wire_bytes} bytes "
         f"({wire_bytes * 100 // QR_MAX_BYTES_ECC_H}% of the {QR_MAX_BYTES_ECC_H}-byte "
         "level-H ceiling)")
    _out(f"payload           {payload_bytes} bytes "
         f"({payload_bytes * 100 // MAX_PAYLOAD_BYTES}% of the {MAX_PAYLOAD_BYTES}-byte "
         "payload budget)")
    _out(f"signature         {len(decoded.signature)} bytes raw r||s")
    _out(f"  r               {decoded.signature[:32].hex()}")
    _out(f"  s               {decoded.signature[32:].hex()}")
    _out()
    if parsed is None:
        _out("payload is not valid JSON:")
        _out(payload_text[:400])
    else:
        _out("payload:")
        for line in json.dumps(parsed, indent=2, ensure_ascii=False).splitlines():
            _out(f"  {line}")
    _out()
    # An inspector that stayed quiet about this would invite someone to read
    # "inspect succeeded" as "the code is genuine".
    _out("signature          NOT CHECKED — inspect only decodes. Use `verify`.")
    return EXIT_OK


# ── selftest ──────────────────────────────────────────────────────────────────


def cmd_selftest(args: argparse.Namespace) -> int:
    """End-to-end round trip with no network, no pytest, and no key set on disk.

    This is the command to run on demo day before anyone is watching: it proves
    signing, tampering detection, expiry, unknown keys, verdict precedence and
    the capacity gate all still behave, in about a second.
    """
    passed = 0
    failed = 0

    def check(label: str, condition: bool, detail: str = "") -> None:
        nonlocal passed, failed
        if condition:
            passed += 1
            _out(f"  [ok]   {label}")
        else:
            failed += 1
            _out(f"  [FAIL] {label}" + (f" — {detail}" if detail else ""))

    today = date.today()
    licence = "MH/25D/2019/187"
    maker = "Sanjeevani Pharma Ltd, Plot 42 MIDC, Pune 411018"

    def sample(**overrides: Any) -> MedicineData:
        fields: dict[str, Any] = {
            "product_id": "PARACETAMOL500MG_SELFTEST500_2026_000001",
            "generic_name": "Paracetamol 500mg",
            "brand_name": "Selftest 500",
            "manufacturer": maker,
            "mfg_licence_no": licence,
            "batch_no": "ST26H0001",
            "mfg_date": (today - timedelta(days=120)).isoformat(),
            "expiry_date": (today + timedelta(days=545)).isoformat(),
            "quantity": "10 tablets",
            "excipients": ["Maize Starch", "Povidone K30", "Talc"],
            "med_type": TYPE_MEDICINE,
        }
        fields.update(overrides)
        return MedicineData(**fields)

    _out("TrueMed selftest")
    _out()
    _out("key set and trust bundle")
    with TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        namespace = argparse.Namespace(
            out=str(tmp_dir), licence=licence, manufacturer="Sanjeevani Pharma Ltd",
            add=False, force=False, encrypt=False, valid_years=5,
            key_password_file=None, key_password_env=DEFAULT_PASSWORD_ENV,
        )
        # keygen prints its own report; that output is part of what is being tested,
        # so it is not suppressed.
        code = cmd_keygen(namespace)
        check("keygen exits 0", code == EXIT_OK, f"exit {code}")

        keyset = KeySet.load(tmp_dir)
        check("keyset lists exactly one signer", len(keyset.signers) == 1)

        root_public = load_public_key((tmp_dir / ROOT_PUBLIC_FILENAME).read_bytes())
        bundle = TrustBundle.from_json(
            (tmp_dir / BUNDLE_FILENAME).read_text(encoding="utf-8"),
            root_public_key=root_public,
            require_signature=True,
        )
        check("trust bundle verifies under the root key", len(bundle) == 1)

        tampered_bundle_json = (tmp_dir / BUNDLE_FILENAME).read_text(encoding="utf-8")
        tampered_bundle_json = tampered_bundle_json.replace(
            "Sanjeevani Pharma Ltd", "Counterfeit Pharma Ltd"
        )
        try:
            TrustBundle.from_json(
                tampered_bundle_json, root_public_key=root_public, require_signature=True
            )
            check("tampered trust bundle is rejected", False, "it was accepted")
        except TrueMedError:
            check("tampered trust bundle is rejected", True)

        private_key = keyset.private_key_for(licence, namespace)

        _out()
        _out("signing and verification")
        good = sample()
        wire = build_wire(good, private_key)
        result = verify_wire(wire, bundle, today=today)
        check("genuine code verifies", result.valid, result.error or "")
        check("verdict is SIGNATURE_VALID_OFFLINE",
              result.verdict == "SIGNATURE_VALID_OFFLINE", result.verdict)
        check("offline success is not reported as GENUINE",
              result.verdict != "GENUINE", "offline cannot rule out a cloned QR")

        decoded = decode_wire(wire)
        check("payload survives the wire round trip",
              decoded.payload_bytes == good.canonical_json())
        check("canonical JSON is byte-stable across constructions",
              sample().canonical_json() == good.canonical_json())

        # Same length so the payload stays valid JSON: this must fail on the
        # signature, not on the parse, or the test proves nothing.
        mutated = decoded.payload_bytes.replace(b'"Selftest 500"', b'"Selftest 501"')
        check("tamper fixture changed exactly one byte",
              len(mutated) == len(decoded.payload_bytes)
              and mutated != decoded.payload_bytes)
        forged = encode_wire(mutated, decoded.signature)
        result = verify_wire(forged, bundle, today=today)
        check("tampered payload is COUNTERFEIT", result.verdict == "COUNTERFEIT",
              result.verdict)
        check("the failing check is the signature",
              result.checks.get("signature") == "fail", str(result.checks))

        untrusted = generate_private_key()
        result = verify_wire(build_wire(good, untrusted), bundle, today=today)
        check("code signed by an untrusted key is COUNTERFEIT",
              result.verdict == "COUNTERFEIT", result.verdict)

        unknown_licence = sample(mfg_licence_no="XX/25D/1999/000")
        result = verify_wire(build_wire(unknown_licence, private_key), bundle, today=today)
        check("unknown licence is UNVERIFIABLE, not COUNTERFEIT",
              result.verdict == "UNVERIFIABLE", result.verdict)

        expired = sample(
            mfg_date=(today - timedelta(days=1000)).isoformat(),
            expiry_date=(today - timedelta(days=30)).isoformat(),
        )
        result = verify_wire(build_wire(expired, private_key), bundle, today=today)
        check("expired code is EXPIRED", result.verdict == "EXPIRED", result.verdict)
        check("EXPIRED is a warning, not critical", result.severity == "warn",
              result.severity)

        result = verify_wire("not-a-truemed-code", bundle, today=today)
        check("unrelated QR text is UNVERIFIABLE",
              result.verdict == "UNVERIFIABLE", result.verdict)
        result = verify_wire("TM9.abc.def", bundle, today=today)
        check("a future format version fails closed",
              result.verdict == "UNVERIFIABLE", result.verdict)

        _out()
        _out("verdict precedence with chain evidence")
        offline = verify_wire(wire, bundle, today=today)
        merged = merge_online_evidence(offline, on_chain=True, status="at_pharmacy",
                                       today=today)
        check("on chain and healthy is GENUINE", merged.verdict == "GENUINE",
              merged.verdict)
        check("GENUINE is the only ok severity", merged.severity == "ok", merged.severity)

        merged = merge_online_evidence(offline, on_chain=False, today=today)
        check("valid signature absent from the ledger is COUNTERFEIT",
              merged.verdict == "COUNTERFEIT", merged.verdict)

        merged = merge_online_evidence(offline, on_chain=True, status="recalled",
                                       today=today)
        check("recalled stock is RECALLED", merged.verdict == "RECALLED", merged.verdict)

        merged = merge_online_evidence(offline, on_chain=True, status="at_pharmacy",
                                       scan_count=400, distinct_districts=14, today=today)
        check("400 scans across 14 districts is CLONE_SUSPECTED",
              merged.verdict == "CLONE_SUSPECTED", merged.verdict)

        vaccine = sample(
            product_id="BCGVACCINE_SELFTESTBCG_2026_000002",
            generic_name="BCG Vaccine", brand_name="Selftest BCG",
            med_type=TYPE_VACCINE, quantity="1 vial (20 doses)",
            excipients=["Sodium Glutamate", "Water for Injection"],
        )
        vaccine_offline = verify_wire(build_wire(vaccine, private_key), bundle, today=today)
        merged = merge_online_evidence(
            vaccine_offline, on_chain=True, status="in_transit",
            temperature_readings=[{"temperature": 4.2}, {"temperature": 15.6}],
            today=today,
        )
        check("vaccine above 8 C is COLD_CHAIN_BREACH",
              merged.verdict == "COLD_CHAIN_BREACH", merged.verdict)
        merged = merge_online_evidence(
            vaccine_offline, on_chain=True, status="in_transit",
            temperature_readings=[{"temperature": 2.0}, {"temperature": 8.0}],
            today=today,
        )
        check("2.0 and 8.0 C are inside the inclusive envelope",
              merged.verdict == "GENUINE", merged.verdict)
        merged = merge_online_evidence(
            offline, on_chain=True, status="in_transit",
            temperature_readings=[{"temperature": 31.0}],
            today=today,
        )
        check("a tablet at 31 C is not a cold-chain breach",
              merged.verdict == "GENUINE", merged.verdict)

        merged = merge_online_evidence(offline, on_chain=True, status="recalled",
                                       scan_count=400, distinct_districts=14, today=today)
        check("RECALLED outranks CLONE_SUSPECTED", merged.verdict == "RECALLED",
              merged.verdict)

        forged_offline = verify_wire(forged, bundle, today=today)
        merged = merge_online_evidence(forged_offline, on_chain=True,
                                       status="at_pharmacy", today=today)
        check("chain data cannot rescue a forged signature",
              merged.verdict == "COUNTERFEIT", merged.verdict)

        _out()
        _out("capacity gate")
        try:
            sample(excipients=["क" * 40] * 12)
            check("an over-budget payload is refused", False, "it was accepted")
        except PayloadError as exc:
            check("an over-budget payload is refused", True)
            check("the error explains the byte cost of non-Latin text",
                  "3 bytes per character" in exc.message, exc.message[:80])

        _out()
        _out("PNG rendering")
        try:
            rendered = generate_qr(good, private_key, tmp_dir / "out")
        except TrueMedError as exc:
            if exc.code == "DEPENDENCY_MISSING":
                _out("  [skip] qrcode is not installed — pip install 'qrcode[pil]'")
            else:
                check("PNG renders", False, exc.message)
        else:
            check("PNG file exists",
                  rendered.png_path is not None and rendered.png_path.is_file())
            check("fitted QR version is within the scannable range",
                  rendered.qr_version is not None and rendered.qr_version <= 20,
                  f"version {rendered.qr_version}")

    _out()
    _out(f"passed {passed}   failed {failed}")
    if failed:
        _out()
        _out("Something above is broken. Do not demo until it passes.")
        return EXIT_ERROR
    _out()
    _out("All checks passed. Signing, tamper detection and verdict precedence work.")
    return EXIT_OK


# ── Argument parsing ──────────────────────────────────────────────────────────


def _add_key_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("signing keys")
    group.add_argument(
        "--keys", default=DEFAULT_KEYS_DIR, metavar="DIR",
        help=f"key set directory produced by keygen (default: {DEFAULT_KEYS_DIR}/)",
    )
    group.add_argument(
        "--key", metavar="FILE",
        help="sign with this private key regardless of licence, bypassing the key set",
    )
    _add_password_options(group)


def _add_password_options(group: Any) -> None:
    group.add_argument(
        "--key-password-file", metavar="FILE",
        help="read the private key password from this file",
    )
    group.add_argument(
        "--key-password-env", default=DEFAULT_PASSWORD_ENV, metavar="NAME",
        help=f"environment variable holding the password (default: {DEFAULT_PASSWORD_ENV})",
    )


def _add_bundle_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("trust")
    group.add_argument(
        "--keys", default=DEFAULT_KEYS_DIR, metavar="DIR",
        help=f"directory holding the trust bundle (default: {DEFAULT_KEYS_DIR}/)",
    )
    group.add_argument("--bundle", metavar="FILE", help="path to trust-bundle.json")
    group.add_argument("--root-pub", metavar="FILE", help="root public key PEM")
    group.add_argument(
        "--allow-unsigned-bundle", action="store_true",
        help="skip the bundle's root signature check (local development only)",
    )


def _add_render_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("rendering")
    group.add_argument("--out", default="out", metavar="DIR",
                       help="output directory for PNGs (default: out/)")
    group.add_argument("--no-png", action="store_true",
                       help="produce wire strings only, no image files")
    group.add_argument("--no-manifest", action="store_true",
                       help="skip manifest.json (it is what the API and chain seed read)")
    group.add_argument("--no-caption", action="store_true",
                       help="omit the human-readable caption under the code")
    group.add_argument("--scale", type=int, default=10, metavar="N",
                       help="pixels per QR module (default: 10)")
    group.add_argument("--border", type=int, default=4, metavar="N",
                       help="quiet-zone width in modules, minimum 4 (default: 4)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")


def _add_wire_source(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--wire", metavar="STR", help="the TM1.... string")
    group.add_argument("--image", metavar="FILE", help="a PNG containing the QR code")
    group.add_argument("--stdin", action="store_true", help="read the wire string from stdin")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="TrueMed — CDSCO-format QR generation and offline verification.",
        epilog=(
            "Exit codes:\n"
            "  0  success — including SIGNATURE_VALID_OFFLINE, which is amber in the\n"
            "     app (offline cannot rule out a cloned QR) but is not a failure here\n"
            "  1  operational error: missing key, unreadable file, bad input\n"
            "  2  bad usage\n"
            "  3  verification warning: EXPIRED, UNVERIFIABLE\n"
            "  4  verification critical: COUNTERFEIT, RECALLED, CLONE_SUSPECTED,\n"
            "     COLD_CHAIN_BREACH"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version",
                       version=f"TrueMed QR generator {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # keygen
    keygen = sub.add_parser(
        "keygen", help="create a signing key set and a root-signed trust bundle",
        description=(
            "Creates a root key, one signing key per manufacturing licence, and a "
            "root-signed trust bundle. Run this once. Every other command that signs "
            "requires it."
        ),
    )
    keygen.add_argument("--out", default=DEFAULT_KEYS_DIR, metavar="DIR",
                        help=f"where to write the key set (default: {DEFAULT_KEYS_DIR}/)")
    keygen.add_argument("--licence", metavar="NO",
                        help="create a key for this licence only, instead of the demo set")
    keygen.add_argument("--manufacturer", metavar="NAME",
                        help="manufacturer name for --licence")
    keygen.add_argument("--add", action="store_true",
                        help="append a signer to an existing key set")
    keygen.add_argument("--force", action="store_true",
                        help="discard and regenerate an existing key set")
    keygen.add_argument("--encrypt", action="store_true",
                        help="encrypt the private keys with a password")
    keygen.add_argument("--valid-years", type=int, default=5, metavar="N",
                        help="forward validity from today, in years (default: 5); the "
                             "window also opens 5 years in the past so backdated codes verify")
    _add_password_options(keygen.add_argument_group("password source"))
    keygen.set_defaults(func=cmd_keygen)

    # generate
    gen = sub.add_parser("generate", help="sign one payload and render its QR")
    required = gen.add_argument_group("data elements (all required)")
    required.add_argument("--generic-name", required=True, metavar="STR")
    required.add_argument("--brand-name", required=True, metavar="STR")
    required.add_argument("--manufacturer", required=True, metavar="STR",
                          help="name and address, comma-separated")
    required.add_argument("--mfg-licence-no", required=True, metavar="NO",
                          help="CDSCO manufacturing licence, e.g. MH/25D/2019/187")
    required.add_argument("--batch-no", required=True, metavar="STR")
    required.add_argument("--mfg-date", required=True, metavar="YYYY-MM-DD")
    required.add_argument("--expiry-date", required=True, metavar="YYYY-MM-DD")
    required.add_argument("--quantity", required=True, metavar="STR",
                          help='e.g. "10 tablets", "1 vial (5 doses)"')
    optional = gen.add_argument_group("optional data elements")
    optional.add_argument("--excipient", action="append", metavar="NAME",
                          help="repeat once per excipient; do not comma-separate")
    optional.add_argument("--type", choices=[TYPE_MEDICINE, TYPE_VACCINE],
                          default=TYPE_MEDICINE,
                          help="vaccines get cold-chain evaluation (default: medicine)")
    optional.add_argument("--serial", type=int, default=1, metavar="N",
                          help="unit serial used to build product_id (default: 1)")
    optional.add_argument("--product-id", metavar="ID",
                          help="override the generated product_id")
    _add_key_options(gen)
    _add_render_options(gen)
    gen.set_defaults(func=cmd_generate)

    # batch
    batch = sub.add_parser("batch", help="sign many payloads from a JSON file")
    batch.add_argument("--input", required=True, metavar="FILE",
                       help="JSON array, or an object with medicines/vaccines arrays")
    _add_key_options(batch)
    _add_render_options(batch)
    batch.set_defaults(func=cmd_batch)

    # demo
    demo = sub.add_parser("demo", help="generate the built-in sample catalogue")
    demo.add_argument("--count", type=int, default=5, metavar="N",
                      help="how many catalogue items to generate (default: 5)")
    demo.add_argument("--today", metavar="YYYY-MM-DD",
                      help="treat this as today, for reproducible demo dates")
    _add_key_options(demo)
    _add_render_options(demo)
    demo.set_defaults(func=cmd_demo)

    # verify
    verify = sub.add_parser("verify", help="verify a wire string or a PNG, offline")
    _add_wire_source(verify)
    _add_bundle_options(verify)
    verify.add_argument("--chain-json", metavar="FILE",
                        help="fold in blockchain evidence and recompute the verdict")
    verify.add_argument("--today", metavar="YYYY-MM-DD",
                        help="treat this as today, for reproducible expiry tests")
    verify.add_argument("--json", action="store_true", help="machine-readable output")
    verify.set_defaults(func=cmd_verify)

    # inspect
    inspect = sub.add_parser(
        "inspect", help="decode a wire string without verifying it",
        description="Decodes and reports sizes. Does NOT check the signature.",
    )
    _add_wire_source(inspect)
    inspect.add_argument("--json", action="store_true", help="machine-readable output")
    inspect.set_defaults(func=cmd_inspect)

    # selftest
    selftest = sub.add_parser(
        "selftest", help="end-to-end round trip in a temporary directory",
        description=(
            "Generates keys, signs, tampers, and checks every verdict in a temporary "
            "directory. Needs no network, no key set, and no pytest."
        ),
    )
    selftest.set_defaults(func=cmd_selftest)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_USAGE

    try:
        return int(args.func(args))
    except TrueMedError as exc:
        # Every failure the library raises carries a stable code. Printing it means
        # a caller can grep for SIGNATURE_INVALID rather than for prose.
        _err(f"error: [{exc.code}] {exc.message}")
        return EXIT_ERROR
    except FileNotFoundError as exc:
        _err(f"error: file not found: {exc.filename}")
        return EXIT_ERROR
    except PermissionError as exc:
        _err(f"error: permission denied: {exc.filename}")
        return EXIT_ERROR
    except OSError as exc:
        _err(f"error: {exc}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        _err("interrupted")
        return EXIT_ERROR
    except BrokenPipeError:
        # `python main.py demo | head` closes the pipe early. Exiting quietly is
        # correct; letting it propagate prints a traceback for a normal event.
        return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
