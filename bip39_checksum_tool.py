#!/usr/bin/env python3
"""Safe BIP39 mnemonic validator.

This utility validates a BIP39 phrase using the official 2048-word English or
Spanish lists and checks the checksum embedded in the mnemonic.

Allowed use:
- validating mnemonics that you own or are authorized to test
- checking that a BIP39 mnemonic is syntactically and checksum-valid
- deriving a seed from a valid phrase

Not allowed:
- guessing or brute-forcing someone else's wallet mnemonic
- creating a recovery or attack tool against other users' wallets
"""

from __future__ import annotations

import argparse
import hashlib
import json
from multiprocessing import Pool, cpu_count
from pathlib import Path

try:
    from mnemonic import Mnemonic
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "Missing dependency: 'mnemonic'. Install it with: pip install mnemonic"
    ) from exc

VALID_LANGS = {"en", "es"}


def load_candidates(path: str):
    """Read one mnemonic per line from a file."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    with file_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            phrase = line.strip()
            if phrase:
                yield phrase


def checksum_from_entropy(entropy_hex: str):
    """Return the expected checksum bits for a BIP39 entropy value."""
    entropy_bytes = bytes.fromhex(entropy_hex)
    checksum_size = len(entropy_bytes) * 8 // 32
    checksum = hashlib.sha256(entropy_bytes).digest()
    checksum_int = int.from_bytes(checksum, "big")
    return checksum_int >> (256 - checksum_size)


def decode_mnemonic(phrase: str, language: str):
    """Validate phrase + checksum and return normalized data."""
    clean_phrase = " ".join(phrase.strip().split())
    if not clean_phrase:
        return {"phrase": phrase, "valid": False, "checksum_ok": False, "reason": "empty phrase"}

    wordlist = Mnemonic(language)
    if not wordlist.check(clean_phrase):
        return {
            "phrase": clean_phrase,
            "valid": False,
            "language": language,
            "checksum_ok": False,
            "reason": "wordlist or checksum mismatch",
        }

    entropy_hex = wordlist.to_entropy(clean_phrase)
    entropy_bits = len(entropy_hex) * 4
    expected_checksum = checksum_from_entropy(entropy_hex)
    words = clean_phrase.split()
    words_count = len(words)

    return {
        "phrase": clean_phrase,
        "valid": True,
        "language": language,
        "checksum_ok": True,
        "word_count": words_count,
        "entropy_bits": entropy_bits,
        "expected_checksum_bits": expected_checksum,
        "seed_hex": hashlib.pbkdf2_hmac("sha512", clean_phrase.encode("utf-8"), b"mnemonic", 2048).hex(),
    }


def _validate_worker(args):
    phrase, language = args
    return decode_mnemonic(phrase, language)


def batch_validate(candidates, language: str, cpu_threads: int):
    """Validate many candidate mnemonics in parallel."""
    if cpu_threads < 1:
        raise ValueError("cpu_threads must be >= 1")

    tasks = [(candidate, language) for candidate in candidates]
    with Pool(processes=cpu_threads) as pool:
        return pool.map(_validate_worker, tasks)


def derive_seed(phrase: str, language: str, passphrase: str = ""):
    """Derive a BIP39 seed from a valid mnemonic."""
    result = decode_mnemonic(phrase, language)
    if not result["valid"]:
        raise ValueError(f"Invalid mnemonic for {language}: {phrase}")

    salt = b"mnemonic" + passphrase.encode("utf-8")
    seed_bytes = hashlib.pbkdf2_hmac("sha512", phrase.encode("utf-8"), salt, 2048)
    return {
        "phrase": phrase,
        "language": language,
        "passphrase": passphrase,
        "seed_hex": seed_bytes.hex(),
    }


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Validate BIP39 mnemonics using the standard 2048-word English or Spanish lists "
            "and confirm the embedded checksum is correct."
        )
    )
    parser.add_argument(
        "--language",
        choices=sorted(VALID_LANGS),
        default="en",
        help="BIP39 word list: en or es",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="Validate one mnemonic phrase")
    validate_parser.add_argument("phrase", help="Mnemonic phrase to validate")

    batch_parser = subparsers.add_parser("batch", help="Validate multiple mnemonics from a file")
    batch_parser.add_argument("--input", required=True, help="File with one mnemonic per line")
    batch_parser.add_argument(
        "--cpu-threads",
        type=int,
        default=min(8, cpu_count()),
        help="Number of CPU workers for batch validation",
    )
    batch_parser.add_argument(
        "--cuda-device",
        type=int,
        default=None,
        help="Optional GPU device index for a CUDA-enabled environment. This script does not brute-force wallets.",
    )

    derive_parser = subparsers.add_parser("derive", help="Derive a BIP39 seed from a valid mnemonic")
    derive_parser.add_argument("phrase", help="Mnemonic phrase")
    derive_parser.add_argument("--passphrase", default="", help="Optional BIP39 passphrase")

    return parser


def main():
    args = build_parser().parse_args()

    if args.command == "validate":
        result = decode_mnemonic(args.phrase, args.language)
        if not result["valid"]:
            print(json.dumps({"valid": False, "checksum_ok": False, "language": args.language, "phrase": args.phrase}, ensure_ascii=False))
            return 1

        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "batch":
        try:
            candidates = list(load_candidates(args.input))
        except FileNotFoundError as exc:
            print(str(exc))
            return 2

        if args.cuda_device is not None:
            try:
                import cupy  # noqa: F401
                print(f"CUDA device {args.cuda_device} requested. CuPy is available, but validation remains CPU-driven for safety and compatibility.")
            except ImportError:
                print(f"GPU request ignored because CuPy is not installed; using CPU workers only.")

        results = batch_validate(candidates, args.language, args.cpu_threads)
        valid = [r for r in results if r.get("valid")]
        print(json.dumps({
            "language": args.language,
            "processed": len(results),
            "valid_count": len(valid),
            "first_valid_examples": valid[:10],
        }, ensure_ascii=False, indent=2))
        return 0

    if args.command == "derive":
        try:
            derived = derive_seed(args.phrase, args.language, args.passphrase)
        except ValueError as exc:
            print(str(exc))
            return 1

        print(json.dumps(derived, ensure_ascii=False, indent=2))
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
""