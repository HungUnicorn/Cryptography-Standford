# AES Modes of Operation: Decryption

It provides a "from-scratch" implementation of **AES-CBC** (Cipher Block Chaining) and **AES-CTR** (Counter) decryption modes using Python. 

The goal was to understand the underlying mechanics of how block ciphers process multi-block messages, specifically focusing on the XOR chaining in CBC and keystream generation in CTR.

## 🛠 Features

* **Custom CBC Decryption:** Manually handles IV extraction and block-by-block XOR chaining.
* **Custom CTR Decryption:** Implements counter-based keystream generation, converting the AES block cipher into a stream cipher.
* **Hex Input Support:** Functions are designed to handle standard hex-encoded strings directly.
* **Unit Tested:** Includes a full suite of tests based on the Stanford Applied Cryptography assignment vectors.

---

### Comparison of Decryption Logic

In **CBC mode**, each block of ciphertext is decrypted and then XORed with the *previous* ciphertext block. This creates a dependency chain.



In **CTR mode**, the block cipher is used to encrypt a "counter" to create a keystream, which is then XORed with the ciphertext. This allows for parallel processing and random access.



---
### 📝 Implementation Notes

**PKCS#7 Padding**: The decrypt_cbc function returns the raw bytes, which includes the padding. In a production environment, this would typically be removed using an unpad function.

**Block Primitives**: Both modes utilize AES.new(key, AES.MODE_ECB) as the underlying engine. This is intentional to ensure the "Chaining" and "Counter" logic is implemented manually rather than by the library.

**Stream Cipher Property**: CTR mode does not require padding because it treats the data as a stream of bits.