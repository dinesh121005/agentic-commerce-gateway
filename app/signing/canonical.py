"""
RFC 8785 JSON Canonicalization Scheme (JCS) Implementation.

Guarantees byte-for-byte deterministic serialization across languages and platforms:
- Whitespace: No whitespace characters outside string literals.
- Property Sorting: Object keys sorted lexicographically by UTF-16 code units.
- Character Encoding: Strict UTF-8 output.
- String Escaping: Minimal JSON escaping rules per RFC 8785 §3.2.2.2.
- Number Representation: Integers formatted without exponent/decimal; floats shortest form.
"""
import hashlib
from typing import Any, Dict


def rfc8785_canonicalize(data: Any) -> bytes:
    """
    Serializes a Python object to canonical JSON bytes according to RFC 8785 (JCS).
    Returns UTF-8 encoded bytes.
    """
    def serialize(val: Any) -> str:
        if val is None:
            return "null"
        elif isinstance(val, bool):
            return "true" if val else "false"
        elif isinstance(val, int):
            return str(val)
        elif isinstance(val, float):
            if val.is_integer():
                return str(int(val))
            # Format shortest representation without trailing zeros or unnecessary exponent
            return repr(val)
        elif isinstance(val, str):
            out = ['"']
            for c in val:
                cp = ord(c)
                if c == '"':
                    out.append('\\"')
                elif c == '\\':
                    out.append('\\\\')
                elif c == '\b':
                    out.append('\\b')
                elif c == '\f':
                    out.append('\\f')
                elif c == '\n':
                    out.append('\\n')
                elif c == '\r':
                    out.append('\\r')
                elif c == '\t':
                    out.append('\\t')
                elif cp < 0x20:
                    out.append(f"\\u{cp:04x}")
                else:
                    out.append(c)
            out.append('"')
            return "".join(out)
        elif isinstance(val, (list, tuple)):
            return "[" + ",".join(serialize(x) for x in val) + "]"
        elif isinstance(val, dict):
            # Keys sorted lexicographically by UTF-16 code units (RFC 8785 §3.2.3)
            sorted_keys = sorted(val.keys(), key=lambda k: k.encode("utf-16-be"))
            items = []
            for k in sorted_keys:
                if not isinstance(k, str):
                    raise TypeError(f"Dictionary keys must be strings, got {type(k)}")
                items.append(serialize(k) + ":" + serialize(val[k]))
            return "{" + ",".join(items) + "}"
        else:
            raise TypeError(f"Unsupported type for RFC 8785 canonicalization: {type(val)}")

    return serialize(data).encode("utf-8")


def canonical_json_hash(data: Any) -> str:
    """Computes lowercase SHA-256 hex digest of RFC 8785 canonical JSON bytes."""
    return hashlib.sha256(rfc8785_canonicalize(data)).hexdigest()


def build_signing_bytes(domain_separator: str, payload: Any) -> bytes:
    """
    Constructs the exact deterministic Ed25519 signing input:
    SigningBytes = DomainSeparatorBytes || CanonicalJsonBytes
    With zero extra whitespace, newlines, or delimiters.
    """
    domain_bytes = domain_separator.encode("utf-8")
    canonical_bytes = rfc8785_canonicalize(payload)
    return domain_bytes + canonical_bytes

