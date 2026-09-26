import re, sys

def strip_rust(s):
    out = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        # line comment
        if c == "/" and i + 1 < n and s[i+1] == "/":
            j = s.find("\n", i)
            i = n if j < 0 else j
            continue
        # block comment (non-nested approximation)
        if c == "/" and i + 1 < n and s[i+1] == "*":
            j = s.find("*/", i+2)
            i = n if j < 0 else j + 2
            continue
        # raw string r#"..."# or r"..."
        if c == "r" and (i == 0 or not (s[i-1].isalnum() or s[i-1] == "_")):
            k = i + 1
            hashes = 0
            while k < n and s[k] == "#":
                hashes += 1; k += 1
            if k < n and s[k] == '"':
                term = '"' + "#" * hashes
                j = s.find(term, k + 1)
                i = n if j < 0 else j + len(term)
                continue
        # byte/char/string literal  b'x' 'x' b"x" "x"
        if c == "'":
            # char literal 'x' / '\n' / '\'' — but a lifetime ('a, 'static)
            # has no closing quote after one char, so fall through as text.
            j = i + 1
            if j < n and s[j] == "\\":
                k = j + 2
                while k < n and s[k] != "'":
                    k += 1
                if k < n:
                    i = k + 1
                    continue
            elif j + 1 < n and s[j + 1] == "'":
                i = j + 2
                continue
            out.append(c)
            i += 1
            continue
        if c == '"' or (c == "b" and i + 1 < n and s[i + 1] == '"'):
            j = i + (2 if c == "b" else 1)
            while j < n:
                if s[j] == "\\":
                    j += 2
                    continue
                if s[j] == '"':
                    j += 1
                    break
                j += 1
            i = j
            continue
        if c == "b" and i + 1 < n and s[i + 1] == "'":
            j = i + 2
            if j < n and s[j] == "\\":
                k = j + 2
                while k < n and s[k] != "'":
                    k += 1
                if k < n:
                    i = k + 1
                    continue
            elif j + 1 < n and s[j + 1] == "'":
                i = j + 2
                continue
        out.append(c)
        i += 1
    return "".join(out)

for p in sys.argv[1:]:
    s = strip_rust(open(p, encoding="utf-8", errors="replace").read())
    o, cl = s.count("{"), s.count("}")
    print(f"{'OK' if o==cl else 'IMBALANCE'}  {p}  {{={o} }}={cl} delta={o-cl}")
