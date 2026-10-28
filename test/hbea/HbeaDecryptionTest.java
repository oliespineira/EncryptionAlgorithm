package hbea;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Task 5: BDD scenarios (Given - When - Then) for HBEA decryption.
 */
@DisplayName("Feature: HBEA decryption")
class HbeaDecryptionTest {
    private static final String OFFICIAL_EMAIL = StudentConfig.EMAIL;
    private static final String OTHER_EMAIL = StudentConfig.OTHER_EMAIL;
    private static final String VECTOR_EMAIL = "student@student.ie.edu";
    private static final String VECTOR_MESSAGE = "Meet me at the library at 5 PM!!";
    private static final String VECTOR_CIPHERTEXT =
            "AB980FB8275358AE1D411D5FF38B89E5DCAD224E7282B8A8FF7A945EE97A5D40";

    @Nested
    @DisplayName("Scenario: test vectors from Section 7")
    class TestVectors {
        @Test
        @DisplayName("Given the spec key and message, When I encrypt, Then I get the spec ciphertext")
        void encryptMatchesSpec() throws Exception {
            Cipher cipher = new HbeaCipher(VECTOR_EMAIL);
            assertEquals(VECTOR_CIPHERTEXT, cipher.encrypt(VECTOR_MESSAGE));
        }

        @Test
        @DisplayName("Given the spec ciphertext, When I decrypt with the spec key, Then I get the spec message")
        void decryptMatchesSpec() {
            Cipher cipher = new HbeaCipher(VECTOR_EMAIL);
            assertEquals(VECTOR_MESSAGE, cipher.decrypt(VECTOR_CIPHERTEXT));
        }
    }

    @Nested
    @DisplayName("Scenario: correct key")
    class CorrectKey {
        @Test
        @DisplayName("Given my e-mail and a 32-character message, When I encrypt and then decrypt, Then I get the original back")
        void fullMessageRoundTrip() throws Exception {
            Cipher sender = new HbeaCipher(OFFICIAL_EMAIL);
            Cipher receiver = new HbeaCipher(OFFICIAL_EMAIL);   // separate object, same key
            String message = "Meet me at the library at 5pm!!!";
            assertEquals(message, receiver.decrypt(sender.encrypt(message)));
        }

        @Test
        @DisplayName("Given a short message, When I encrypt and then decrypt, Then the padding is removed")
        void shortMessagePaddingRemoved() throws Exception {
            Cipher cipher = new HbeaCipher(OFFICIAL_EMAIL);
            String decrypted = cipher.decrypt(cipher.encrypt("Hi Anas"));
            assertEquals("Hi Anas", decrypted);
            assertEquals(7, decrypted.length());
        }

        @Test
        @DisplayName("Given a message ending in spaces, When I round-trip it, Then the user's spaces are kept")
        void trailingSpacesKept() throws Exception {
            Cipher cipher = new HbeaCipher(OFFICIAL_EMAIL);
            assertEquals("hello   ", cipher.decrypt(cipher.encrypt("hello   ")));
        }

        @Test
        @DisplayName("Given the first letter of my name, When I round-trip it, Then I get \"L\" back")
        void firstLetterRoundTrip() throws Exception {
            Cipher cipher = new HbeaCipher(OFFICIAL_EMAIL);
            assertEquals("L", cipher.decrypt(cipher.encrypt("L")));
        }

        @Test
        @DisplayName("Given any cipher, When I use the default method verifyRoundTrip, Then it returns true")
        void defaultMethodWorks() throws Exception {
            Cipher cipher = new HbeaCipher(OFFICIAL_EMAIL);
            assertTrue(cipher.verifyRoundTrip("Interfaces are cool!"));
        }
    }

    @Nested
    @DisplayName("Scenario: wrong key")
    class WrongKey {
        @Test
        @DisplayName("Given a ciphertext, When I decrypt with a different e-mail, Then the original is NOT recovered")
        void differentEmailFails() throws Exception {
            String message = "Meet me at the library at 5pm!!!";
            String ciphertext = new HbeaCipher(OFFICIAL_EMAIL).encrypt(message);
            String attempt = new HbeaCipher(OTHER_EMAIL).decrypt(ciphertext);
            assertNotEquals(message, attempt);
        }

        @Test
        @DisplayName("Given the spec ciphertext, When I decrypt with my e-mail, Then the spec message is NOT recovered")
        void specCiphertextWithWrongKey() {
            assertNotEquals(VECTOR_MESSAGE, new HbeaCipher(OFFICIAL_EMAIL).decrypt(VECTOR_CIPHERTEXT));
        }
    }

    @Nested
    @DisplayName("Scenario: round keys in reverse order")
    class ReverseKeys {
        @Test
        @DisplayName("Given an encrypted block, When decryption runs, Then its first state equals encryption's last state swapped")
        void decryptionUndoesEncryptionRoundByRound() throws Exception {
            HbeaCipher cipher = new HbeaCipher(OFFICIAL_EMAIL);
            int[] block = BitUtils.fromHex("4D656574206D6520");          // "Meet me "
            int[][] enc = cipher.trace(block);
            String cipherBlock = cipher.encrypt(BitUtils.fromHex(
                    "4D656574206D6520" + "0".repeat(48))).substring(0, 16);
            int[][] dec = cipher.traceDecryption(BitUtils.fromHex(cipherBlock));

            // After IP, decryption starts at (R8, L8): the swapped final state of encryption
            String last = BitUtils.toHex(enc[HbeaCipher.ROUNDS]);
            assertEquals(last.substring(8) + last.substring(0, 8), BitUtils.toHex(dec[0]));
            // ... and finishes at (R0, L0): the swapped first state of encryption
            String first = BitUtils.toHex(enc[0]);
            assertEquals(first.substring(8) + first.substring(0, 8), BitUtils.toHex(dec[HbeaCipher.ROUNDS]));
        }
    }

    @Nested
    @DisplayName("Scenario: invalid ciphertext")
    class InvalidCiphertext {
        @Test
        @DisplayName("Given a ciphertext with the wrong length, When I decrypt, Then an IllegalArgumentException is thrown")
        void wrongLength() {
            Cipher cipher = new HbeaCipher(OFFICIAL_EMAIL);
            assertThrows(IllegalArgumentException.class, () -> cipher.decrypt("ABC"));
        }

        @Test
        @DisplayName("Given a ciphertext with a non-hex character, When I decrypt, Then an IllegalArgumentException is thrown")
        void nonHex() {
            Cipher cipher = new HbeaCipher(OFFICIAL_EMAIL);
            assertThrows(IllegalArgumentException.class, () -> cipher.decrypt("Z".repeat(64)));
        }
    }
}

/* Test results (JUnit 5):
PASS  Scenario: invalid ciphertext > Given a ciphertext with the wrong length, When I decrypt, Then an IllegalArgumentException is thrown
PASS  Scenario: invalid ciphertext > Given a ciphertext with a non-hex character, When I decrypt, Then an IllegalArgumentException is thrown
PASS  Scenario: round keys in reverse order > Given an encrypted block, When decryption runs, Then its first state equals encryption's last state swapped
PASS  Scenario: wrong key > Given a ciphertext, When I decrypt with a different e-mail, Then the original is NOT recovered
PASS  Scenario: wrong key > Given the spec ciphertext, When I decrypt with my e-mail, Then the spec message is NOT recovered
PASS  Scenario: correct key > Given my e-mail and a 32-character message, When I encrypt and then decrypt, Then I get the original back
PASS  Scenario: correct key > Given a short message, When I encrypt and then decrypt, Then the padding is removed
PASS  Scenario: correct key > Given the first letter of my name, When I round-trip it, Then I get "L" back
PASS  Scenario: correct key > Given any cipher, When I use the default method verifyRoundTrip, Then it returns true
PASS  Scenario: correct key > Given a message ending in spaces, When I round-trip it, Then the user's spaces are kept
PASS  Scenario: test vectors from Section 7 > Given the spec key and message, When I encrypt, Then I get the spec ciphertext
PASS  Scenario: test vectors from Section 7 > Given the spec ciphertext, When I decrypt with the spec key, Then I get the spec message
12 tests successful, 0 failed
*/
