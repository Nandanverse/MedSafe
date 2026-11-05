#!/usr/bin/env python3
"""Static cross-check for the Dart verification core.

No Dart toolchain is available in this sandbox, so this script substitutes for the
part of `dart analyze` that catches the errors that actually happen when porting a
module by hand between languages:

  1. a symbol used without importing the file that declares it
     (this found the missing `import 'ecdsa.dart'` in verifier.dart)
  2. a static member that does not exist on the class it is read from
     (`Codes.internal` for `Codes.internalError`, `Verdict.isKnown` before it was
     added)
  3. an import that nothing in the file uses
  4. control characters embedded in a source file

It is a regex approximation of a resolver, not a parser, so it errs toward
reporting too much: everything it prints is triaged by hand. What it must never do
is stay silent about a genuine unresolved name.
"""
import os
import re
import sys
from collections import defaultdict

CORE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lib', 'core')

# Names supplied by the SDK and by pointycastle. Anything here is assumed to exist;
# the point of the script is our own code, not the platform's.
EXTERNAL = {
    # dart:core
    'Object', 'String', 'int', 'double', 'num', 'bool', 'List', 'Map', 'Set',
    'Iterable', 'Iterator', 'DateTime', 'Duration', 'RegExp', 'RegExpMatch',
    'BigInt', 'StringBuffer', 'Exception', 'Error', 'FormatException',
    'TypeError', 'StateError', 'ArgumentError', 'RangeError',
    'UnsupportedError', 'UnimplementedError', 'Comparable', 'Function',
    'Runes', 'Symbol', 'Type', 'Null', 'Never', 'dynamic', 'void',
    'identical', 'print', 'override', 'pragma', 'deprecated', 'Deprecated',
    'assert', 'const', 'final', 'true', 'false', 'null', 'this', 'super',
    # dart:convert
    'jsonDecode', 'jsonEncode', 'json', 'utf8', 'ascii', 'latin1',
    'base64', 'base64Url', 'base64Decode', 'base64Encode', 'Utf8Encoder',
    'Utf8Decoder', 'JsonEncoder', 'JsonDecoder', 'LineSplitter',
    # dart:typed_data
    'Uint8List', 'Uint16List', 'Uint32List', 'Int8List', 'ByteData',
    'Endian', 'TypedData',
    # pointycastle
    'SHA256Digest', 'SHA1Digest', 'Digest', 'HMac', 'Mac', 'KeyParameter',
    'ECDSASigner', 'ECPublicKey', 'ECPrivateKey', 'ECSignature',
    'ECDomainParameters', 'ECPoint', 'ECCurve', 'PublicKeyParameter',
    'PrivateKeyParameter', 'Signer', 'CipherParameters', 'ParametersWithRandom',
    'SecureRandom', 'FortunaRandom',
}

# Static/enum-ish members on external types that we read.
EXTERNAL_MEMBERS = {
    'DateTime': {'now', 'utc', 'parse', 'tryParse', 'fromMillisecondsSinceEpoch',
                 'fromMicrosecondsSinceEpoch', 'timestamp'},
    'BigInt': {'parse', 'tryParse', 'from', 'zero', 'one', 'two'},
    'Uint8List': {'fromList', 'view', 'sublistView'},
    'List': {'unmodifiable', 'from', 'of', 'filled', 'generate', 'empty',
             'castFrom', 'copyRange', 'writeIterable'},
    'Map': {'unmodifiable', 'from', 'of', 'fromEntries', 'fromIterable',
            'castFrom', 'identity'},
    'Set': {'unmodifiable', 'from', 'of', 'identity', 'castFrom'},
    'String': {'fromCharCode', 'fromCharCodes', 'fromEnvironment'},
    'int': {'parse', 'tryParse', 'fromEnvironment'},
    'double': {'parse', 'tryParse', 'infinity', 'nan', 'maxFinite', 'minPositive',
               'negativeInfinity'},
    'bool': {'fromEnvironment', 'hasEnvironment', 'parse', 'tryParse'},
    'RegExp': {'escape'},
    'Duration': {'zero', 'microsecondsPerSecond', 'millisecondsPerSecond',
                 'secondsPerMinute', 'minutesPerHour', 'hoursPerDay'},
    'Object': {'hash', 'hashAll', 'hashAllUnordered'},
    'Endian': {'big', 'little', 'host'},
    'base64': {'decode', 'encode', 'normalize', 'encoder', 'decoder'},
    'base64Url': {'decode', 'encode', 'normalize', 'encoder', 'decoder'},
    'utf8': {'decode', 'encode', 'encoder', 'decoder'},
    'json': {'decode', 'encode'},
}

DECL_PATTERNS = [
    # class / mixin / enum / extension / typedef
    (re.compile(r'^(?:abstract\s+)?(?:final\s+|base\s+|sealed\s+|interface\s+)*'
                r'class\s+(\w+)', re.M), 'class'),
    (re.compile(r'^enum\s+(\w+)', re.M), 'class'),
    (re.compile(r'^mixin\s+(\w+)', re.M), 'class'),
    (re.compile(r'^typedef\s+(\w+)', re.M), 'class'),
    # top-level const / final / late with an explicit type or var
    (re.compile(r'^(?:const|final)\s+(?:[\w<>,?\s]+?\s+)?(\w+)\s*=', re.M), 'var'),
    # top-level function: returnType name(...)  or  returnType name<T>(...)
    (re.compile(r'^([\w<>,?\[\]]+(?:\s*\?)?)\s+(\w+)\s*(?:<[^>(]*>)?\s*\(', re.M),
     'func'),
    # top-level getter
    (re.compile(r'^[\w<>,?]+\s+get\s+(\w+)\s*=>', re.M), 'func'),
]


def read(path):
    with open(path, 'r', encoding='utf-8') as handle:
        return handle.read()


def strip_comments_and_strings(text):
    """Blank out comments and string literals, preserving line structure.

    Interpolation `$name` and `${expr}` inside strings is kept, because a symbol
    referenced only from an interpolation still has to resolve.
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        two = text[i:i + 2]
        if two == '//':
            j = text.find('\n', i)
            j = n if j < 0 else j
            out.append(' ' * (j - i))
            i = j
        elif two == '/*':
            j = text.find('*/', i + 2)
            j = n if j < 0 else j + 2
            out.append(''.join(c if c == '\n' else ' ' for c in text[i:j]))
            i = j
        elif text[i] in '"\'':
            quote = text[i]
            triple = text[i:i + 3] in ('"""', "'''")
            delim = quote * 3 if triple else quote
            j = i + len(delim)
            buf = [' ' * len(delim)]
            while j < n:
                if text[j] == '\\':
                    buf.append('  ')
                    j += 2
                    continue
                if text[j:j + len(delim)] == delim:
                    j += len(delim)
                    break
                if text[j] == '$':
                    # keep the interpolated expression, blank the '$'
                    if j + 1 < n and text[j + 1] == '{':
                        depth = 0
                        k = j + 1
                        while k < n:
                            if text[k] == '{':
                                depth += 1
                            elif text[k] == '}':
                                depth -= 1
                                if depth == 0:
                                    k += 1
                                    break
                            k += 1
                        buf.append('  ' + text[j + 2:k - 1] + ' ')
                        j = k
                        continue
                    m = re.match(r'\$(\w+(?:\.\w+)*)', text[j:])
                    if m:
                        buf.append(' ' + m.group(1))
                        j += m.end()
                        continue
                buf.append('\n' if text[j] == '\n' else ' ')
                j += 1
            out.append(''.join(buf))
            i = j
        else:
            out.append(text[i])
            i += 1
    return ''.join(out)


def find_class_bodies(code):
    """name -> body text, by brace matching from the class declaration."""
    bodies = {}
    for m in re.finditer(
            r'^(?:abstract\s+)?(?:final\s+|base\s+|sealed\s+|interface\s+)*'
            r'(?:class|enum|mixin)\s+(\w+)[^{;]*', code, re.M):
        name = m.group(1)
        brace = code.find('{', m.end() - 1 if m.end() > m.start() else m.start())
        if brace < 0:
            continue
        depth = 0
        i = brace
        while i < len(code):
            if code[i] == '{':
                depth += 1
            elif code[i] == '}':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        bodies[name] = code[brace:i]
    return bodies


def class_members(cls, body):
    """Members reachable as `Cls.member`: statics, constructors, factories."""
    members = set()
    # Everything between `static` and the `=`/`(`/`;`/`=>` that ends the
    # declaration, taking the last identifier. Written this way because a declared
    # type can contain spaces — `static const Map<String, String> toWire = ...` —
    # which a `[\w<>]+` type pattern silently fails to match, making every generic
    # static look undeclared.
    for m in re.finditer(r'\bstatic\b[^;={]*?(\w+)\s*(?:=>|=|\(|;)', body):
        members.add(m.group(1))
    for m in re.finditer(r'\bstatic\b[^;={]*?\bget\s+(\w+)', body):
        members.add(m.group(1))
    # named constructors and factories: `factory Cls.name(` / `Cls.name(`
    for m in re.finditer(r'\b(?:factory\s+)?' + re.escape(cls) + r'\.(\w+)\s*\(',
                         body):
        members.add(m.group(1))
    return members


def instance_members(body):
    """Names declared inside a class body, however declared.

    Used only to suppress false positives on unqualified calls to a class's own
    methods (`canonicalJSONString()` inside MedicineData), so it is deliberately
    over-inclusive: a missed name here costs a spurious warning, never a missed one.
    """
    names = set()
    for m in re.finditer(r'(?:^|\s)([\w<>,?\[\]]+\s+)?(\w+)\s*\(', body):
        names.add(m.group(2))
    for m in re.finditer(r'\bget\s+(\w+)', body):
        names.add(m.group(1))
    for m in re.finditer(r'\bfinal\b[^;=]*?(\w+)\s*[;=]', body):
        names.add(m.group(1))
    return names


def main():
    files = sorted(f for f in os.listdir(CORE) if f.endswith('.dart'))
    src = {f: read(os.path.join(CORE, f)) for f in files}
    code = {f: strip_comments_and_strings(t) for f, t in src.items()}

    # ── control characters ────────────────────────────────────────────────────
    problems = []
    for f, text in src.items():
        raw = text.encode('utf-8')
        for idx, byte in enumerate(raw):
            if byte < 0x20 and byte not in (0x09, 0x0a, 0x0d):
                line = raw[:idx].count(b'\n') + 1
                problems.append(
                    f'{f}:{line}: control byte 0x{byte:02x} in source')
                break

    # ── declarations ──────────────────────────────────────────────────────────
    declares = defaultdict(set)          # file -> names
    kind_of = {}                         # (file, name) -> kind
    bodies = {}                          # file -> {class: body}
    members = defaultdict(dict)          # file -> {class: members}
    own_members = defaultdict(set)       # file -> names declared inside any class
    for f, text in code.items():
        for pattern, kind in DECL_PATTERNS:
            for m in pattern.finditer(text):
                name = m.group(2) if pattern.groups == 2 else m.group(1)
                if name in ('if', 'for', 'while', 'switch', 'return', 'catch',
                            'else', 'do', 'try', 'import', 'export', 'library',
                            'part', 'get', 'set', 'operator', 'new'):
                    continue
                declares[f].add(name)
                kind_of[(f, name)] = kind
        bodies[f] = find_class_bodies(text)
        for cls, body in bodies[f].items():
            members[f][cls] = class_members(cls, body)
            own_members[f] |= instance_members(body)

    # ── imports ───────────────────────────────────────────────────────────────
    # Read from the RAW source, not the stripped code: stripping blanks string
    # literals, and an import path *is* a string literal. Anchored at the start of
    # a line so an `import` inside a doc-comment example (which is prefixed by
    # `/// `) is not mistaken for a real one.
    imports = {}                         # file -> {target: prefix or None}
    for f, text in src.items():
        found = {}
        for m in re.finditer(
                r"^import\s+'([^']+)'(?:\s+as\s+(\w+))?[^;]*;", text, re.M):
            found[m.group(1)] = m.group(2)
        imports[f] = found

    # visible top-level names and classes per file
    visible = {}
    visible_members = {}
    prefixed = {}
    for f in files:
        names = set(declares[f])
        cls_members = dict(members[f])
        pref = {}
        for target, prefix in imports[f].items():
            if not target.endswith('.dart') or '/' in target:
                continue
            if target not in src:
                problems.append(f'{f}: imports {target}, which does not exist')
                continue
            if prefix:
                pref[prefix] = target
            else:
                names |= declares[target]
                for cls, mem in members[target].items():
                    cls_members.setdefault(cls, mem)
        visible[f] = names
        visible_members[f] = cls_members
        prefixed[f] = pref

    # ── usage: static member access on our own classes ────────────────────────
    for f, text in code.items():
        for m in re.finditer(r'(?<![\w.$])([A-Z]\w*)\.(\w+)', text):
            cls, member = m.group(1), m.group(2)
            line = text[:m.start()].count('\n') + 1
            if cls in visible_members[f]:
                known = visible_members[f][cls]
                if member not in known and member not in ('new',):
                    problems.append(
                        f'{f}:{line}: {cls}.{member} is not a static member of '
                        f'{cls} (has: {", ".join(sorted(known)) or "none"})')
            elif cls in EXTERNAL:
                known = EXTERNAL_MEMBERS.get(cls)
                if known is not None and member not in known:
                    problems.append(
                        f'{f}:{line}: {cls}.{member} unknown on SDK type {cls}')
            elif cls not in prefixed[f]:
                problems.append(
                    f'{f}:{line}: type {cls} is not declared, imported or known '
                    f'(in {cls}.{member})')

    # ── usage: prefixed access must resolve in the prefixed library ───────────
    for f, text in code.items():
        for prefix, target in prefixed[f].items():
            for m in re.finditer(r'(?<![\w.$])' + prefix + r'\.(\w+)', text):
                name = m.group(1)
                line = text[:m.start()].count('\n') + 1
                if name not in declares[target]:
                    problems.append(
                        f'{f}:{line}: {prefix}.{name} is not declared in {target}')

    # ── usage: type annotations ───────────────────────────────────────────────
    # A bare `TrueMedPublicKey publicKey;` is neither a call nor a member access, so
    # neither check above sees it. This is the one that catches a missing import for
    # a type that is only ever named, and it is how the absent `ecdsa.dart` import
    # in verifier.dart would have been found from the declaration rather than from
    # the call site.
    for f, text in code.items():
        reported = set()
        for m in re.finditer(r'(?<![\w.$])([A-Z]\w{2,})(?![\w.])', text):
            name = m.group(1)
            if name in visible[f] or name in EXTERNAL or name in prefixed[f]:
                continue
            if name in visible_members[f] or name in own_members[f]:
                continue
            if name in reported:
                continue
            reported.add(name)
            line = text[:m.start()].count('\n') + 1
            owner = next((o for o in files
                          if o != f and name in declares[o]), None)
            where = (f'declared in {owner}, which is not imported here'
                     if owner else 'not declared anywhere in lib/core')
            problems.append(f'{f}:{line}: type {name} is {where}')


    # ── usage: bare identifiers that look like calls ─────────────────────────
    for f, text in code.items():
        # words that are declared somewhere in the core but not visible here
        elsewhere = {}
        for other in files:
            if other == f:
                continue
            for name in declares[other]:
                elsewhere.setdefault(name, other)
        for m in re.finditer(r'(?<![\w.$])([a-zA-Z_]\w*)\s*\(', text):
            name = m.group(1)
            if name in visible[f] or name in EXTERNAL:
                continue
            if name in own_members[f]:
                # a class calling its own method unqualified
                continue
            if name in ('if', 'for', 'while', 'switch', 'catch', 'return',
                        'assert', 'super', 'this', 'get', 'set', 'is', 'as',
                        'in', 'new', 'throw', 'await', 'yield', 'else', 'do',
                        'try', 'rethrow', 'operator', 'factory', 'const',
                        'final', 'var', 'void', 'static', 'late', 'required'):
                continue
            if name in elsewhere:
                line = text[:m.start()].count('\n') + 1
                problems.append(
                    f'{f}:{line}: {name}() is declared in {elsewhere[name]} but '
                    f'that file is not imported here')

    # ── unused imports ────────────────────────────────────────────────────────
    for f, text in code.items():
        for target, prefix in imports[f].items():
            if not target.endswith('.dart') or target not in src:
                continue
            if prefix:
                if not re.search(r'(?<![\w.$])' + prefix + r'\.', text):
                    problems.append(f'{f}: import of {target} as {prefix} is unused')
                continue
            used = False
            for name in declares[target]:
                if re.search(r'(?<![\w.$])' + re.escape(name) + r'\b', text):
                    used = True
                    break
            if not used:
                problems.append(f'{f}: import of {target} appears unused')

    print(f'checked {len(files)} files, '
          f'{sum(len(v) for v in declares.values())} top-level declarations, '
          f'{sum(len(v) for v in members.values())} classes')
    print()
    if not problems:
        print('no unresolved references found')
        return 0
    for p in problems:
        print(p)
    print()
    print(f'{len(problems)} item(s) to triage')
    return 1


if __name__ == '__main__':
    sys.exit(main())
