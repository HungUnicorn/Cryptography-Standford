import unittest

from src.aes_decryption.aes_decryption import decrypt_cbc, decrypt_ctr


class TestAESDecryption(unittest.TestCase):

    # --- Test Data (Shared across tests) ---
    def setUp(self):
        self.cbc_key = "140b41b22a29beb4061bda66b6747e14"
        self.ctr_key = "36f18357be4dbd77f050515c73fcf9f2"

    # --- CBC Tests ---
    def test_cbc_problem_1(self):
        ct = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
        expected = b'Basic CBC mode encryption needs padding.\x08\x08\x08\x08\x08\x08\x08\x08'
        self.assertEqual(decrypt_cbc(ct, self.cbc_key), expected)

    def test_cbc_problem_2(self):
        ct = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
        expected = b'Our implementation uses rand. IV\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
        self.assertEqual(decrypt_cbc(ct, self.cbc_key), expected)

    # --- CTR Tests ---
    def test_ctr_problem_3(self):
        ct = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
        expected = b'CTR mode lets you build a stream cipher from a block cipher.'
        self.assertEqual(decrypt_ctr(ct, self.ctr_key), expected)

    def test_ctr_problem_4(self):
        ct = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
        expected = b'Always avoid the two time pad!'
        self.assertEqual(decrypt_ctr(ct, self.ctr_key), expected)


if __name__ == '__main__':
    unittest.main()
