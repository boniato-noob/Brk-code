# BIP39 checksum validator

This repository contains a legitimate, safety-focused Python utility that validates mnemonic phrases from the official English or Spanish BIP39 2048-word lists and checks that the embedded checksum is correct.

Important:
- This tool is intended for legitimate wallet validation and testing of user-owned mnemonics.
- It does not include brute-force, wallet guessing, or recovery logic.
- It checks whether a phrase is a valid BIP39 mnemonic and whether its checksum matches the expected value.

## Features

- Validates one mnemonic phrase
- Validates a batch of phrases from a file
- Supports `en` and `es` 2048-word lists
- Uses CPU threads via `--cpu-threads`
- Accepts an optional `--cuda-device` flag for CUDA-capable environments, without enabling brute-force behavior
- Derives a BIP39 seed from a valid mnemonic

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Example: validate one mnemonic

```bash
python bip39_checksum_tool.py --language en validate "abandon ability able about above absent absorb abstract absurd abuse access accident"
```

## Example: validate a batch file

```bash
python bip39_checksum_tool.py --language es batch --input candidates.txt --cpu-threads 8
```

## Example: derive the seed

```bash
python bip39_checksum_tool.py --language en derive "abandon ability able about above absent absorb abstract absurd abuse access accident" --passphrase "demo-passphrase"
```

The checksum validation logic is based on the standard BIP39 rule: entropy bits + checksum bits produce the mnemonic, and the checksum must match the SHA-256 hash of the entropy.
