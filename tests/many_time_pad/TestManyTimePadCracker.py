import unittest
from unittest.mock import patch

from src.many_time_pad.ManyTimePadCracker import ManyTimePadCracker


class TestManyTimePadCracker(unittest.TestCase):

    def setUp(self):
        """
        Set up a controlled environment for each test.
        """
        self.known_key_str = "SECRET"
        self.known_key_bytes = self.known_key_str.encode('ascii')

        self.plaintexts = [
            "Hello World",
            "This is fun",
            "Crypto test",
            "Unittestng!",  # Intentional typo/grammar to vary chars
            " Python 3.9",
            "       pad ",  # Lots of spaces help the algorithm
        ]
        self.target_plaintext = "Target Msg!"

        self.ciphers_hex = [self._encrypt(p, self.known_key_bytes) for p in self.plaintexts]
        self.target_hex = self._encrypt(self.target_plaintext, self.known_key_bytes)

        self.cracker = ManyTimePadCracker(self.ciphers_hex, self.target_hex)

    def _encrypt(self, plaintext, key):
        """Helper to simulate the One-Time Pad encryption."""
        pt_bytes = plaintext.encode('ascii')
        ct_bytes = bytearray()
        for i in range(len(pt_bytes)):
            k = key[i % len(key)]
            ct_bytes.append(pt_bytes[i] ^ k)
        return ct_bytes.hex()

    # ======================================================
    # TEST HELPER METHODS
    # ======================================================

    def test_initialization(self):
        """Does it parse hex correctly?"""
        expected_first_cipher = bytes.fromhex(self.ciphers_hex[0])
        self.assertEqual(self.cracker.ciphers[0], expected_first_cipher)
        self.assertEqual(len(self.cracker.all_msgs), len(self.plaintexts) + 1)

    def test_get_column_bytes(self):
        """Does it handle columns and padding correctly?"""
        # "       pad " is shorter (11 chars) than "Unittestng!" (11 chars)...
        # Let's add a short message to verify None padding manually.
        short_hex = self._encrypt("Hi", self.known_key_bytes)
        local_cracker = ManyTimePadCracker([short_hex], self.target_hex)

        # Column 0: Should have data
        col_0 = local_cracker._get_column_bytes(0)
        self.assertIsNotNone(col_0[0])

        # Column 100: Should be None (out of bounds)
        col_100 = local_cracker._get_column_bytes(100)
        self.assertIsNone(col_100[0])

    def test_score_key_candidate(self):
        key_byte = ord('X')
        plain_char = ord('e')
        cipher_byte = plain_char ^ key_byte
        col_bytes = [cipher_byte] * 10  # More samples to be safe

        # 1. Test with CORRECT key
        score = self.cracker._score_key_candidate(key_byte, col_bytes)
        self.assertEqual(score, 1.0)

        # 2. Test with WRONG key (Use Bit Flip instead of +1)
        # Flipping bits usually pushes ASCII letters into negative/control territory
        wrong_key = key_byte ^ 0xFF

        score_wrong = self.cracker._score_key_candidate(wrong_key, col_bytes)
        self.assertLess(score_wrong, 1.0)

    # ======================================================
    # TEST CORE LOGIC
    # ======================================================

    def test_solve_key_recovery(self):
        """Can it recover the 'SECRET' key from our statistical noise?"""
        self.cracker.solve_key()

        # Check the first few bytes of the recovered key
        # We know the key is "SECRET", so key[0] should be 'S', key[1] 'E'...
        recovered_key_prefix = ""
        for k in self.cracker.key[:6]:
            if k is not None:
                recovered_key_prefix += chr(k)
            else:
                recovered_key_prefix += "_"

        print(f"\nRecovered Key: {recovered_key_prefix}")
        self.assertEqual(recovered_key_prefix, "SECRET")

    def test_decrypt_target_logic(self):
        """Does decryption produce the right string with placeholders?"""
        # Manually force the key to match our known key
        # (skipping solve_key to test decryption in isolation)
        self.cracker.key = [k for k in self.known_key_bytes]
        # Extend key to match target length (since our helper repeats the key)
        while len(self.cracker.key) < len(self.target_plaintext):
            self.cracker.key.append(self.known_key_bytes[len(self.cracker.key) % 6])

        decrypted = self.cracker.decrypt_target()
        self.assertEqual(decrypted, self.target_plaintext)

    def test_decrypt_with_missing_key(self):
        """Does it output '_' when key is missing?"""
        self.cracker.key = [None] * len(self.target_plaintext)

        decrypted = self.cracker.decrypt_target()
        self.assertEqual(decrypted[0], "_")

    # ======================================================
    # TEST MOCKING (LLM)
    # ======================================================

    @patch('ollama.generate')
    def test_fix_with_llm(self, mock_ollama):
        """Verify we call the LLM correctly and return its result."""
        # Setup the mock to return a fake response
        mock_ollama.return_value = {'response': 'Corrected Sentence'}

        broken_text = "Br_ken T_xt"
        result = self.cracker.fix_with_llm(broken_text)

        mock_ollama.assert_called_once()

        self.assertEqual(result, 'Corrected Sentence')


if __name__ == '__main__':
    unittest.main()