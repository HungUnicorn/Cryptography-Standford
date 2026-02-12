# Stanford Cryptography - Course Exercises 🎓

This repository contains my personal implementations and solutions for the programming assignments from the **Stanford University Cryptography** course. 

The goal of this project is to explore cryptographic vulnerabilities, implement standard algorithms from scratch, and understand the mathematical foundations of secure communication through hands-on coding.

---

## 📂 Project Structure

Each directory represents a specific exercise or cryptographic concept covered in the course.

| Exercise / Project                        | Concept        | Description                                                                            | Status |
|:------------------------------------------|:---------------|:---------------------------------------------------------------------------------------| :--- |
| **[ManyTimePad](./src/many_time_pad)**    | Stream Ciphers | Breaking Many-Time Pad reuse using statistical "Space Voting" and LLM post-processing. | ✅ Completed |
| **[AesDecryption](./src/aes_decryption)** | Block Ciphers  | Implementation of CBC and CTR modes to understand stream-based counter logic.          | ✅ Completed |
---

## 🛠️ General Setup

### Requirements
* **Python 3.10+**
* **Ollama**

## 🧪 Running Tests
Verification is a key part of these exercises. Each module includes a unittest suite to ensure the cryptographic logic is sound.
