# Copied unchanged from DefinedNet/packaging lib/kms_pgp.py. Fix bugs there first.
"""Sign files using AWS KMS keys, producing OpenPGP-compatible signatures.

This module wraps an AWS KMS RSA key and produces:
  - Armored PGP public key blocks (for gpg.asc)
  - Detached signatures (for Release.gpg)
  - Clearsigned messages (for InRelease)

No private key material ever leaves KMS. Required KMS permissions:
kms:Sign, kms:GetPublicKey, kms:DescribeKey, kms:ListResourceTags.

Usage:
  from kms_pgp import KmsPgpSigner
  signer = KmsPgpSigner("alias/MyKey")
  signer.export_public_key("gpg.asc")
  signer.sign("Release", "Release.gpg")
  signer.clearsign("Release", "InRelease")
"""

import hashlib
import struct
import time
from base64 import b64encode
from pathlib import Path

import boto3

# ── OpenPGP constants (RFC 4880) ────────────────────────────────────────────

_KEY_VERSION = 4
_SIG_VERSION = 4
_ALGO_RSA = 1
_HASH_SHA256 = 8

_TAG_SIGNATURE = 2
_TAG_PUBLIC_KEY = 6
_TAG_USER_ID = 13

_SIGTYPE_BINARY = 0x00
_SIGTYPE_TEXT = 0x01
_SIGTYPE_POSITIVE_KEY = 0x13

_SUB_CREATION_TIME = 2
_SUB_KEY_FLAGS = 27
_SUB_HASH_ALGOS = 21
_SUB_ISSUER = 16
_SUB_ISSUER_FINGERPRINT = 33


# ── OpenPGP packet encoding ─────────────────────────────────────────────────


def _mpi(n: int) -> bytes:
    """Encode an integer as an OpenPGP MPI (multi-precision integer)."""
    bit_len = n.bit_length()
    byte_len = (bit_len + 7) // 8
    return struct.pack(">H", bit_len) + n.to_bytes(byte_len, "big")


def _subpacket(tag: int, data: bytes) -> bytes:
    """Encode an OpenPGP signature subpacket."""
    body = bytes([tag]) + data
    length = len(body)
    if length < 192:
        return bytes([length]) + body
    raise ValueError(f"Subpacket too long: {length}")


def _packet(tag: int, body: bytes) -> bytes:
    """Encode an OpenPGP packet using old-format headers."""
    length = len(body)
    if length <= 0xFF:
        header = bytes([0x80 | (tag << 2) | 0, length])
    elif length <= 0xFFFF:
        header = bytes([0x80 | (tag << 2) | 1]) + struct.pack(">H", length)
    else:
        header = bytes([0x80 | (tag << 2) | 2]) + struct.pack(">I", length)
    return header + body


def _armor(label: str, data: bytes) -> bytes:
    """ASCII-armor binary OpenPGP data."""
    # CRC24
    crc = 0xB704CE
    for b in data:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    crc &= 0xFFFFFF

    encoded = b64encode(data).decode()
    lines = [encoded[i : i + 76] for i in range(0, len(encoded), 76)]
    checksum = b64encode(crc.to_bytes(3, "big")).decode()

    parts = [
        f"-----BEGIN PGP {label}-----",
        "",
        *lines,
        f"={checksum}",
        f"-----END PGP {label}-----",
        "",
    ]
    return "\n".join(parts).encode()


# ── RSA public key DER parsing ───────────────────────────────────────────────


def _parse_der_length(data: bytes, offset: int) -> tuple[int, int]:
    """Parse a DER length field, return (length, new_offset)."""
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    num_bytes = first & 0x7F
    length = int.from_bytes(data[offset + 1 : offset + 1 + num_bytes], "big")
    return length, offset + 1 + num_bytes


def _parse_der_integer(data: bytes, offset: int) -> tuple[int, int]:
    """Parse a DER INTEGER, return (value, new_offset)."""
    if data[offset] != 0x02:
        raise ValueError(f"Expected INTEGER tag (0x02), got 0x{data[offset]:02x}")
    length, offset = _parse_der_length(data, offset + 1)
    value = int.from_bytes(data[offset : offset + length], "big")
    return value, offset + length


def _extract_rsa_pubkey(der: bytes) -> tuple[int, int]:
    """Extract (modulus, exponent) from a DER-encoded SubjectPublicKeyInfo."""
    # SEQUENCE (SubjectPublicKeyInfo)
    offset = 0
    if der[offset] != 0x30:
        raise ValueError("Expected SEQUENCE")
    _, offset = _parse_der_length(der, offset + 1)

    # SEQUENCE (AlgorithmIdentifier) - skip it
    if der[offset] != 0x30:
        raise ValueError("Expected SEQUENCE for AlgorithmIdentifier")
    algo_len, algo_offset = _parse_der_length(der, offset + 1)
    offset = algo_offset + algo_len

    # BIT STRING (subjectPublicKey)
    if der[offset] != 0x03:
        raise ValueError("Expected BIT STRING")
    bs_len, offset = _parse_der_length(der, offset + 1)
    if der[offset] != 0x00:  # unused bits must be 0
        raise ValueError("Expected 0 unused bits in BIT STRING")
    offset += 1

    # Inside the BIT STRING: SEQUENCE containing modulus and exponent
    if der[offset] != 0x30:
        raise ValueError("Expected SEQUENCE for RSAPublicKey")
    _, offset = _parse_der_length(der, offset + 1)

    modulus, offset = _parse_der_integer(der, offset)
    exponent, offset = _parse_der_integer(der, offset)
    return modulus, exponent


# ── KMS PGP Signer ──────────────────────────────────────────────────────────


class KmsPgpSigner:
    """Wraps an AWS KMS RSA key for OpenPGP signing operations."""

    def __init__(self, key_id: str, user_id: str = "", region: str | None = None):
        """Initialize with a KMS key ID, ARN, or alias.

        Args:
            key_id: KMS key ID, ARN, or alias (e.g. "alias/MyKey")
            user_id: PGP user ID string (e.g. "Name <email>").
                     If empty, fetched from KMS tags PGPName/PGPEmail.
            region: AWS region. If None, uses default from environment.
        """
        kwargs = {}
        if region:
            kwargs["region_name"] = region
        self._kms = boto3.client("kms", **kwargs)

        # Fetch public key material
        resp = self._kms.get_public_key(KeyId=key_id)
        self._arn = resp["KeyId"]
        der = resp["PublicKey"]

        # Validate key type
        spec = resp["KeySpec"]
        if spec not in ("RSA_2048", "RSA_3072", "RSA_4096"):
            raise ValueError(f"Unsupported key spec: {spec}. Need RSA_2048/3072/4096.")

        self._modulus, self._exponent = _extract_rsa_pubkey(der)

        # Get creation date
        meta = self._kms.describe_key(KeyId=self._arn)
        self._created = int(meta["KeyMetadata"]["CreationDate"].timestamp())

        # Build user ID
        if user_id:
            self._user_id = user_id
        else:
            self._user_id = self._user_id_from_tags()

    def _user_id_from_tags(self) -> str:
        try:
            resp = self._kms.list_resource_tags(KeyId=self._arn)
        except Exception:
            return f"KMS Key ({self._arn})"

        name = email = None
        for tag in resp.get("Tags", []):
            if tag["TagKey"] == "PGPName":
                name = tag["TagValue"]
            elif tag["TagKey"] == "PGPEmail":
                email = tag["TagValue"]

        if name and email:
            return f"{name} <{email}>"
        return name or email or f"KMS Key ({self._arn})"

    @property
    def _pgp_key_body(self) -> bytes:
        """OpenPGP v4 public key packet body."""
        return (
            bytes([_KEY_VERSION])
            + struct.pack(">I", self._created)
            + bytes([_ALGO_RSA])
            + _mpi(self._modulus)
            + _mpi(self._exponent)
        )

    @property
    def _fingerprint(self) -> bytes:
        """OpenPGP v4 key fingerprint (SHA-1 of 0x99 + length + key body)."""
        body = self._pgp_key_body
        h = hashlib.sha1()
        h.update(b"\x99")
        h.update(struct.pack(">H", len(body)))
        h.update(body)
        return h.digest()

    @property
    def _key_id(self) -> bytes:
        """Low 8 bytes of fingerprint."""
        return self._fingerprint[-8:]

    def _kms_sign(self, digest: bytes) -> int:
        """Sign a SHA-256 digest via KMS, return signature as integer."""
        resp = self._kms.sign(
            KeyId=self._arn,
            Message=digest,
            MessageType="DIGEST",
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )
        return int.from_bytes(resp["Signature"], "big")

    def _build_signature_packet(
        self, sig_type: int, hashed_data_fn, extra_hashed_subpackets: bytes = b"", sig_time: int = 0
    ) -> bytes:
        """Build a complete OpenPGP signature packet.

        Args:
            sig_type: Signature type byte
            hashed_data_fn: Callable that takes a hasher and updates it with
                           the data to be signed (before trailer).
            extra_hashed_subpackets: Additional subpackets to include.
            sig_time: Signature creation timestamp. 0 means use current time.
        """
        if sig_time == 0:
            sig_time = int(time.time())
        hasher = hashlib.sha256()

        # Hashed subpackets
        hashed_subs = (
            _subpacket(_SUB_ISSUER_FINGERPRINT, b"\x04" + self._fingerprint)
            + _subpacket(_SUB_CREATION_TIME, struct.pack(">I", sig_time))
            + extra_hashed_subpackets
        )

        # Signature packet header (through hashed subpackets)
        sig_header = (
            bytes([_SIG_VERSION, sig_type, _ALGO_RSA, _HASH_SHA256]) + struct.pack(">H", len(hashed_subs)) + hashed_subs
        )

        # Hash: data + sig_header + trailer
        hashed_data_fn(hasher)
        hasher.update(sig_header)
        hasher.update(b"\x04\xff")
        hasher.update(struct.pack(">I", len(sig_header)))
        digest = hasher.digest()

        # Sign via KMS
        sig_int = self._kms_sign(digest)

        # Unhashed subpackets
        unhashed_subs = _subpacket(_SUB_ISSUER, self._key_id)

        # Complete signature packet body
        body = (
            sig_header
            + struct.pack(">H", len(unhashed_subs))
            + unhashed_subs
            + digest[:2]  # left 16 bits of hash
            + _mpi(sig_int)
        )
        return body

    def export_public_key(self, output_path: str) -> None:
        """Export the PGP public key to a file."""
        key_body = self._pgp_key_body
        uid = self._user_id.encode("utf-8")

        # Self-signature
        extra_subs = (
            _subpacket(_SUB_KEY_FLAGS, b"\x03")  # certify + sign
            + _subpacket(_SUB_HASH_ALGOS, bytes([_HASH_SHA256]))
        )

        def hash_fn(hasher):
            # Key
            hasher.update(b"\x99")
            hasher.update(struct.pack(">H", len(key_body)))
            hasher.update(key_body)
            # User ID
            hasher.update(b"\xb4")
            hasher.update(struct.pack(">I", len(uid)))
            hasher.update(uid)

        sig_body = self._build_signature_packet(_SIGTYPE_POSITIVE_KEY, hash_fn, extra_subs, sig_time=self._created)

        message = _packet(_TAG_PUBLIC_KEY, key_body) + _packet(_TAG_USER_ID, uid) + _packet(_TAG_SIGNATURE, sig_body)

        Path(output_path).write_bytes(_armor("PUBLIC KEY BLOCK", message))

    def sign_bytes(self, data: bytes) -> bytes:
        """Create a binary OpenPGP signature packet for the given data.

        Returns the raw packet bytes (not armored), suitable for embedding
        in RPM signature headers.
        """

        def hash_fn(hasher):
            hasher.update(data)

        sig_body = self._build_signature_packet(_SIGTYPE_BINARY, hash_fn)
        return _packet(_TAG_SIGNATURE, sig_body)

    def sign(self, input_path: str, output_path: str) -> None:
        """Create a detached signature (Release.gpg)."""
        data = Path(input_path).read_bytes()

        def hash_fn(hasher):
            hasher.update(data)

        sig_body = self._build_signature_packet(_SIGTYPE_BINARY, hash_fn)
        message = _packet(_TAG_SIGNATURE, sig_body)

        Path(output_path).write_bytes(_armor("SIGNATURE", message))

    def clearsign(self, input_path: str, output_path: str) -> None:
        """Create a clearsigned message (InRelease)."""
        text = Path(input_path).read_text()
        lines = text.splitlines()

        def hash_fn(hasher):
            for i, line in enumerate(lines):
                # RFC 4880 section 7.1: strip trailing whitespace, use \r\n
                stripped = line.rstrip(" \t").encode("utf-8")
                hasher.update(stripped)
                # No trailing \r\n after the last line
                if i < len(lines) - 1:
                    hasher.update(b"\r\n")

        sig_body = self._build_signature_packet(_SIGTYPE_TEXT, hash_fn)
        sig_armor = _armor("SIGNATURE", _packet(_TAG_SIGNATURE, sig_body))

        # Build clearsigned message
        out_lines = ["-----BEGIN PGP SIGNED MESSAGE-----", "Hash: SHA256", ""]
        for line in lines:
            # RFC 4880 section 7.1: dash-escape lines starting with -
            if line.startswith("-"):
                line = "- " + line
            out_lines.append(line)
        out_lines.append("")

        output = "\n".join(out_lines).encode() + sig_armor
        Path(output_path).write_bytes(output)
