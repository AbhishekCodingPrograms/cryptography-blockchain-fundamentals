"""Assignment 2: hashing, digital signatures, and vehicle registration."""

import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)


def sha256_message(message):
    """Hash the exact UTF-8 message, including spaces and empty messages."""
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


class DigitalSignature:
    def __init__(self):
        self.private_key = None

    def generate_keys(self):
        self.private_key = Ed25519PrivateKey.generate()
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()

    def sign(self, message):
        if self.private_key is None:
            raise ValueError("Generate a key pair before signing a message.")
        return self.private_key.sign(message.encode("utf-8")).hex()

    @staticmethod
    def verify(message, signature_hex, public_key_hex):
        try:
            signature = bytes.fromhex(signature_hex)
            public_bytes = bytes.fromhex(public_key_hex)
        except ValueError as error:
            raise ValueError("Signature and public key must contain hexadecimal characters.") from error
        if len(signature) != 64:
            raise ValueError("An Ed25519 signature must be 64 bytes (128 hex digits).")
        if len(public_bytes) != 32:
            raise ValueError("An Ed25519 public key must be 32 bytes (64 hex digits).")
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        try:
            public_key.verify(signature, message.encode("utf-8"))
            return True
        except InvalidSignature:
            return False


@dataclass(frozen=True)
class Vehicle:
    number_plate: str
    owner: str
    model: str


class VehicleRegistry:
    def __init__(self):
        self.vehicles = {}

    @staticmethod
    def normalize_plate(number_plate):
        # Ignore spaces, hyphens, and case when comparing plates.
        plate = "".join(number_plate.upper().split()).replace("-", "")
        if not plate or not plate.isascii() or not plate.isalnum():
            raise ValueError("Number plate must contain letters or digits; spaces and hyphens are allowed.")
        return plate

    def register(self, number_plate, owner, model):
        plate = self.normalize_plate(number_plate)
        owner, model = owner.strip(), model.strip()
        if not owner or not model:
            raise ValueError("Owner name and model cannot be empty.")
        if plate in self.vehicles:
            raise ValueError("A vehicle with this number plate is already registered.")
        vehicle = Vehicle(plate, owner, model)
        self.vehicles[plate] = vehicle
        return vehicle

    def retrieve(self, number_plate):
        plate = self.normalize_plate(number_plate)
        if plate not in self.vehicles:
            raise ValueError("No vehicle found with this number plate.")
        return self.vehicles[plate]


MENU = """
=== Cryptography and Blockchain Fundamentals ===
1. Generate SHA-256 Hash
2. Generate Public-Private Key Pair
3. Sign a Message
4. Verify a Digital Signature
5. Register Vehicle (Store)
6. Retrieve Vehicle (Get)
7. Exit
"""


def main():
    signatures = DigitalSignature()
    registry = VehicleRegistry()
    print("Keys and vehicle records are kept in memory for this session.")
    while True:
        try:
            print(MENU)
            choice = input("Enter your choice (1-7): ").strip()
            if choice == "1":
                print("SHA-256:", sha256_message(input("Message: ")))
            elif choice == "2":
                public_key = signatures.generate_keys()
                print("New Ed25519 key pair generated. The previous key pair, if any, was replaced.")
                print("Public key (hex):", public_key)
            elif choice == "3":
                if signatures.private_key is None:
                    print("Generate a key pair using option 2 first.")
                    continue
                print("Signature (hex):", signatures.sign(input("Message to sign: ")))
            elif choice == "4":
                message = input("Message to verify: ")
                signature = input("Signature (hex): ").strip()
                public_key = input("Public key (hex): ").strip()
                valid = signatures.verify(message, signature, public_key)
                print("Signature is VALID." if valid else "Signature is INVALID.")
            elif choice == "5":
                vehicle = registry.register(input("Number plate: "),
                                            input("Owner name: "), input("Model: "))
                print(f"Vehicle {vehicle.number_plate} registered successfully.")
            elif choice == "6":
                vehicle = registry.retrieve(input("Number plate: "))
                print(f"Number plate: {vehicle.number_plate}\nOwner: {vehicle.owner}\nModel: {vehicle.model}")
            elif choice == "7":
                print("Goodbye!")
                break
            else:
                print("Invalid choice. Please enter a number from 1 to 7.")
        except ValueError as error:
            print(f"Error: {error}")
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break


if __name__ == "__main__":
    main()
