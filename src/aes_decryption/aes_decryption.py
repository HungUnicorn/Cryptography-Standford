from Crypto.Cipher import AES

def xor_bytes(a, b):
    """ Returns a new byte object that is the XOR of two byte objects. """
    return bytes([x ^ y for x, y in zip(a, b)])

def get_blocks(data, block_size=16):
    """Yields 16-byte chunks from the data."""
    for i in range(0, len(data), block_size):
        yield data[i:i+block_size]

def decrypt_cbc(ciphertext_hex, key_hex):
    raw = bytes.fromhex(ciphertext_hex)
    iv, ciphertext = raw[:16], raw[16:]
    key = bytes.fromhex(key_hex)

    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = []
    prev = iv

    for curr_block in get_blocks(ciphertext):
        decrypted = cipher.decrypt(curr_block)
        pt_block = xor_bytes(decrypted, prev)

        plaintext.append(pt_block)
        prev = curr_block

    return b"".join(plaintext)


def decrypt_ctr(ciphertext_hex, key_hex):
    raw = bytes.fromhex(ciphertext_hex)
    iv, ciphertext = raw[:16], raw[16:]
    key = bytes.fromhex(key_hex)

    cipher = AES.new(key, AES.MODE_ECB)
    keystream = []

    ctr_int = int.from_bytes(iv, 'big')

    for _ in get_blocks(ciphertext):
        ctr_block = ctr_int.to_bytes(16, 'big')
        keystream_block = cipher.encrypt(ctr_block)
        keystream.append(keystream_block)
        ctr_int += 1

    full_keystream = b"".join(keystream)
    return xor_bytes(ciphertext, full_keystream)

# --- Data ---

# Problem 1 (CBC)
k1 = "140b41b22a29beb4061bda66b6747e14"
c1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"

# Problem 2 (CBC)
k2 = "140b41b22a29beb4061bda66b6747e14"
c2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"

# Problem 3 (CTR)
k3 = "36f18357be4dbd77f050515c73fcf9f2"
c3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"

# Problem 4 (CTR)
k4 = "36f18357be4dbd77f050515c73fcf9f2"
c4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"

if __name__ == '__main__':
    print("--- Solutions ---")
    print(f"1. {decrypt_cbc(c1, k1)}")
    print(f"2. {decrypt_cbc(c2, k2)}")
    print(f"3. {decrypt_ctr(c3, k3)}")
    print(f"4. {decrypt_ctr(c4, k4)}")
