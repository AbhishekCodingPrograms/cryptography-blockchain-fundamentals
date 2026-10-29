# Cryptography and Blockchain Fundamentals

Assignment 2: a menu-driven Python console application for SHA-256 hashing,
digital signatures, and vehicle registration.

## Setup and run

Requires Python 3.10 or newer.

```console
python -m pip install -r requirements.txt
python main.py
```

On Windows, use `py` instead of `python` if needed.

## Menu

1. Generate SHA-256 Hash: enter a message and display its 64-character hash.
2. Generate Public-Private Key Pair: generate an Ed25519 signing key and show its public key in hexadecimal.
3. Sign a Message: sign the exact message using the current private key and display the signature in hexadecimal.
4. Verify a Digital Signature: enter a message, signature, and public key to check whether the signature is valid.
5. Register Vehicle (Store): enter a number plate, owner name, and model.
6. Retrieve Vehicle (Get): look up the stored owner and model by number plate.
7. Exit.

The menu repeats after every action. Errors are explained without terminating the application.

## Example walkthrough

### Hashing

Choose 1 and enter `abc`. Expected SHA-256 output:

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

### Signing and verification

1. Choose 2 and copy the displayed public key.
2. Choose 3, enter `Hello blockchain`, and copy the displayed signature.
3. Choose 4 and enter the same message, the signature, and the public key.
4. The application displays `Signature is VALID.`
5. Repeat option 4 with a changed message and the original signature/key.
6. The application displays `Signature is INVALID.`

A fresh random key pair is generated each time option 2 is selected. The private
key stays in memory and is never printed or written to disk. Regenerating keys
replaces the current signing key; old signatures can still be verified with their
original public keys. Verification accepts a supplied public key and does not
require generating a local key pair first.

### Vehicle registration

1. Choose 5: plate `MH12AB1234`, owner `Alice`, model `Sedan`.
2. Choose 6 and enter `MH12AB1234` to see the stored owner and model.
3. Registering `mh-12 ab 1234` is rejected as a duplicate of that plate.
4. Retrieving an unknown plate displays a suitable error message.

Plate comparison ignores case, whitespace, and hyphens. Other punctuation is
rejected. Owner and model must be nonblank. This is a generic registry and does
not enforce one country's plate format.

## Implementation

- `hashlib.sha256` hashes the UTF-8 bytes of the exact message, preserving spaces.
- `DigitalSignature` uses the `cryptography` library's Ed25519 implementation.
- Signature verification returns false for a changed message, altered signature,
  or wrong key; malformed hexadecimal or invalid lengths produce input errors.
- `Vehicle` stores the plate, owner, and model.
- `VehicleRegistry` stores vehicles in a dictionary indexed by normalized plate.
- `main()` runs the menu in a loop until Exit or end-of-input.

SHA-256 hashing and digital signing are separate features. The signature uses
Ed25519's own algorithm, rather than manually signing a SHA-256 digest. Signatures
authenticate message integrity; they do not encrypt the message. A public key
must be associated with a trusted identity separately.

All records and signing keys are session-only and reset on exit. The assignment
requests cryptography and a dictionary-based vehicle registry; no distributed
blockchain or consensus network is implemented.

## Tests

```console
python -m unittest -v
```

Tests cover known SHA-256 vectors; empty and Unicode messages; valid and invalid
signatures; wrong keys; malformed inputs; key regeneration; vehicle registration,
normalization, duplicates, and missing records; and the console menu flows.

Tested with Python 3.12.14 and cryptography 50.0.2.

## Reference

The signing API follows the official cryptography documentation:
https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/

## Submission

Submit this repository's GitHub URL in the assignment submission box.
