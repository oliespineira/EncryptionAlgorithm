# HBEA: Hybrid Block Encryption Algorithm (Session 16, Interfaces)

A small secure-messaging tool. A message (max 32 printable ASCII characters) is
encrypted with a key derived from the user's e-mail (SHA-256) using a DES-style
Feistel cipher. The application works with **any** cipher through the `Cipher`
interface, so HBEA can be swapped for the simple `XorCipher` by changing one line.

## How to run

Open the folder in IntelliJ (`src` = sources, `test` = JUnit 5 tests) and run:

| Class | What it shows |
|---|---|
| `Main` | Full console demo: reads e-mail + message, both ciphers, wrong-key test, saving to a file |
| `KeyGenerationDemo` | Task 2: KS1 ... KS8 from the e-mail |
| `XorDemo` | Task 3: XOR errors handled with try/catch |
| `RoundDemo`, `EncryptionDemo` | Task 4: L and R after each round for a block starting with my name |
| `DecryptionDemo` | Task 5: rounds in reverse key order, wrong-key test |
| `ReflectionDemo` | Reflection Q2: why "Hi Anas" gives three identical blocks |

Run all tests: right-click the `test` folder, then *Run 'All Tests'* (135 tests).
To use your own identity, edit the two constants in `StudentConfig.java`.

## Design

| Role | Classes | OOP concept |
|---|---|---|
| The rules | `Cipher`, `KeyGenerator`, `RoundFunction` | Interfaces, default method, constants |
| The template | `AbstractBlockCipher` | Abstract class, template method, overloading (`encrypt(String)` / `encrypt(int[])`) |
| The algorithms | `HbeaCipher`, `XorCipher` | Inheritance, `@Override`, polymorphism, encapsulated key |
| The parts | `Sha256KeyGenerator`, `DesRoundFunction` | Implementing an interface, composition |
| The tools | `BitUtils`, `HbeaTables` | Final utility classes, private constants |
| The application | `SecureMessenger`, `Main`, `MessageArchive` | Programming to an interface, text-file I/O |
| Errors | `InvalidMessageException` | Custom checked exception |

## Error handling (Chapter 14)

* **Custom checked exception**: `InvalidMessageException` for null, empty, too long or non-ASCII messages.
* **Unchecked exceptions**: `IllegalArgumentException` for programming errors (wrong bit lengths, bad hex, null arrays).
* **Exception chaining**: `NoSuchAlgorithmException` is wrapped in an `IllegalStateException` with its cause.
* **try / catch in a loop**: `Main` asks again after an invalid message instead of crashing.
* **finally**: `MessageArchive` always closes its `PrintWriter` / `Scanner`; `Main` reports the end of the file step.
* **FileNotFoundException**: reading a missing file is handled gracefully.

## Test vector (Section 7)

`student@student.ie.edu` + `Meet me at the library at 5 PM!!` gives
`AB980FB8275358AE1D411D5FF38B89E5DCAD224E7282B8A8FF7A945EE97A5D40`
(checked in `HbeaDecryptionTest`).
