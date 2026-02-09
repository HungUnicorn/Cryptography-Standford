# Many-Time Pad Cracker 🔐

---

## 🛡️ The Vulnerability: Key Re-use

A **One-Time Pad** is mathematically unbreakable *only if* the key is used exactly once. When a key $k$ is reused for two messages $m_1$ and $m_2$, an attacker can XOR the ciphertexts $c_1$ and $c_2$ to eliminate the key:

$$c_1 \oplus c_2 = (m_1 \oplus k) \oplus (m_2 \oplus k) = m_1 \oplus m_2$$

The resulting value is the XOR sum of two plaintexts, which reveals linguistic patterns and statistical properties of the underlying language.

[Image of many time pad reuse vulnerability diagram]

---

## ✨ Features

* **Space Voting Algorithm**: Analyzes columns of ciphertext to identify the most likely location of space characters (`0x20`), which are statistically frequent in English.
* **Confidence Thresholding**: Implements an **80% threshold** to ignore noisy statistical outliers, ensuring high-accuracy key recovery.
* **Target Decryption**: Automatically applies the reconstructed key to a specific "target" ciphertext.
* **AI-Assisted Recovery**: Integrates with **Ollama (Qwen2.5)** to intelligently "fill in the blanks" for characters that couldn't be recovered statistically.

---

## ⚙️ How It Works

| Phase | Description |
| :--- | :--- |
| **1. Statistical Analysis** | The script examines each byte column across all ciphertexts. It tests if a byte corresponds to a space; if the resulting characters in other ciphertexts are all valid ASCII letters, the key byte is "voted" as correct. |
| **2. Decryption** | The recovered key is applied to the target. Missing or low-confidence bytes are replaced with underscores (`_`). |
| **3. LLM Cleanup** | The fragmented text (e.g., `Th_ s_cret mess_ge`) is passed to a local LLM to reconstruct the original English sentence. |

---

### Prerequisites
* **Python 3.8+**
* **Ollama**: Ensure the model is running locally:
    ```bash
    ollama pull qwen2.5:14b
    ollama run qwen2.5:14b
    ```
