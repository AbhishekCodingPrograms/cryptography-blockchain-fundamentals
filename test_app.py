import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from main import DigitalSignature, VehicleRegistry, sha256_message, main


class HashTests(unittest.TestCase):
    def test_known_hash(self):
        self.assertEqual(sha256_message("abc"),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_empty_and_exact_input(self):
        self.assertEqual(sha256_message(""),
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertNotEqual(sha256_message("hello"), sha256_message("hello "))
        self.assertEqual(len(sha256_message("नमस्ते")), 64)


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.signer = DigitalSignature()
        self.public_key = self.signer.generate_keys()

    def test_valid_signature_and_empty_message(self):
        for message in ["Hello", "", "नमस्ते"]:
            signature = self.signer.sign(message)
            self.assertTrue(self.signer.verify(message, signature, self.public_key))

    def test_modified_message_signature_and_wrong_key(self):
        signature = self.signer.sign("Original")
        self.assertFalse(self.signer.verify("Changed", signature, self.public_key))
        changed = bytes([bytes.fromhex(signature)[0] ^ 1]) + bytes.fromhex(signature)[1:]
        self.assertFalse(self.signer.verify("Original", changed.hex(), self.public_key))
        other_key = DigitalSignature().generate_keys()
        self.assertFalse(self.signer.verify("Original", signature, other_key))

    def test_missing_key_and_malformed_values(self):
        with self.assertRaises(ValueError):
            DigitalSignature().sign("Message")
        for signature, key in [("zz", self.public_key), ("", self.public_key),
                               ("00" * 64, "bad"), ("00" * 64, "00")]:
            with self.assertRaises(ValueError):
                self.signer.verify("Message", signature, key)

    def test_regeneration_replaces_signing_key(self):
        signature = self.signer.sign("Hello")
        new_key = self.signer.generate_keys()
        self.assertTrue(self.signer.verify("Hello", signature, self.public_key))
        self.assertFalse(self.signer.verify("Hello", signature, new_key))


class VehicleTests(unittest.TestCase):
    def setUp(self):
        self.registry = VehicleRegistry()

    def test_register_retrieve_and_normalize(self):
        vehicle = self.registry.register("mh-12 ab 1234", " Alice ", " Sedan ")
        self.assertEqual(self.registry.retrieve("MH12AB1234"), vehicle)
        self.assertEqual((vehicle.owner, vehicle.model), ("Alice", "Sedan"))

    def test_duplicate_preserves_original(self):
        self.registry.register("MH12AB1234", "Alice", "Sedan")
        with self.assertRaises(ValueError):
            self.registry.register("mh-12 ab 1234", "Bob", "SUV")
        self.assertEqual(self.registry.retrieve("MH12AB1234").owner, "Alice")

    def test_missing_and_blank_fields(self):
        with self.assertRaises(ValueError):
            self.registry.retrieve("UNKNOWN")
        for plate, owner, model in [(" ", "A", "B"), ("!?", "A", "B"),
                                     ("AB1", " ", "B"), ("AB1", "A", " ")]:
            with self.assertRaises(ValueError):
                self.registry.register(plate, owner, model)
        self.assertEqual(self.registry.vehicles, {})


class MenuTests(unittest.TestCase):
    def test_menu_flow_and_error_recovery(self):
        inputs = ["x", "1", "abc", "3", "2", "3", "Hello", "4", "Hello",
                  "bad", "bad", "5", "MH12AB1234", "Alice", "Sedan",
                  "6", "mh-12 ab 1234", "6", "UNKNOWN", "7"]
        output = StringIO()
        with patch("builtins.input", side_effect=inputs), redirect_stdout(output):
            main()
        text = output.getvalue()
        for expected in ["Invalid choice", sha256_message("abc"), "Generate a key pair",
                         "Public key (hex)", "Signature (hex)", "Error:",
                         "registered successfully", "Owner: Alice", "Model: Sedan",
                         "No vehicle found", "Goodbye!"]:
            self.assertIn(expected, text)
        self.assertEqual(text.count("=== Cryptography and Blockchain Fundamentals ==="), 10)

    def test_menu_valid_and_invalid_verification(self):
        signer = DigitalSignature()
        key = signer.generate_keys()
        signature = signer.sign("Hello")
        output = StringIO()
        with patch("builtins.input", side_effect=["4", "Hello", signature, key,
                    "4", "Changed", signature, key, "7"]), redirect_stdout(output):
            main()
        self.assertIn("Signature is VALID.", output.getvalue())
        self.assertIn("Signature is INVALID.", output.getvalue())


if __name__ == "__main__":
    unittest.main()
