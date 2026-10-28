package hbea;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Task 6: tests for the second cipher and for polymorphism through SecureMessenger.
 */
@DisplayName("Feature: XorCipher and polymorphism")
class XorCipherTest {
    private static final String OFFICIAL_EMAIL = StudentConfig.EMAIL;
    private static final String OTHER_EMAIL = StudentConfig.OTHER_EMAIL;
    private static final String MESSAGE = "Meet me at the library at 5pm!!!";

    @Test
    @DisplayName("Given my e-mail, When I encrypt with XOR and decrypt, Then I get the original back")
    void xorRoundTrip() throws Exception {
        Cipher cipher = new XorCipher(OFFICIAL_EMAIL);
        assertEquals(MESSAGE, cipher.decrypt(cipher.encrypt(MESSAGE)));
        assertTrue(cipher.verifyRoundTrip("Hi"));
    }

    @Test
    @DisplayName("Given the spec key, When I XOR-encrypt 8 NUL bytes, Then I get KS1 + KS2 (the key itself)")
    void xorUsesFirst64KeyBits() {
        XorCipher cipher = new XorCipher("student@student.ie.edu");
        String ciphertext = cipher.encrypt(new int[256]);   // all zeros: 0 XOR k = k
        assertEquals("6C099BA09261A2A3", ciphertext.substring(0, 16));
    }

    @Test
    @DisplayName("Given a ciphertext, When I decrypt with a different e-mail, Then the original is NOT recovered")
    void xorWrongKey() throws Exception {
        String ciphertext = new XorCipher(OFFICIAL_EMAIL).encrypt(MESSAGE);
        assertNotEquals(MESSAGE, new XorCipher(OTHER_EMAIL).decrypt(ciphertext));
    }

    @Test
    @DisplayName("Given the same message, When encrypted with HBEA and with XOR, Then the ciphertexts differ")
    void differentAlgorithmsDifferentOutput() throws Exception {
        assertNotEquals(new HbeaCipher(OFFICIAL_EMAIL).encrypt(MESSAGE),
                new XorCipher(OFFICIAL_EMAIL).encrypt(MESSAGE));
    }

    @Test
    @DisplayName("Given SecureMessenger, When I plug in either cipher, Then send/receive works without changing it")
    void secureMessengerWorksWithBothCiphers() throws Exception {
        Cipher[] ciphers = { new HbeaCipher(OFFICIAL_EMAIL), new XorCipher(OFFICIAL_EMAIL) };
        String[] expectedNames = { "HBEA", "XOR" };
        for (int i = 0; i < ciphers.length; i++) {
            SecureMessenger messenger = new SecureMessenger(ciphers[i]);
            assertEquals(expectedNames[i], messenger.getCipherName());
            assertEquals(MESSAGE, messenger.receive(messenger.send(MESSAGE)));
            assertTrue(messenger.selfCheck(MESSAGE));
        }
    }

    @Test
    @DisplayName("Given an invalid message, When I send it, Then InvalidMessageException is thrown")
    void messengerRejectsInvalidMessage() {
        SecureMessenger messenger = new SecureMessenger(new XorCipher(OFFICIAL_EMAIL));
        assertThrows(InvalidMessageException.class, () -> messenger.send(""));
    }

    @Test
    @DisplayName("Given a null cipher or key generator, When I build the object, Then IllegalArgumentException is thrown")
    void nullsRejected() {
        assertThrows(IllegalArgumentException.class, () -> new SecureMessenger(null));
        assertThrows(IllegalArgumentException.class, () -> new XorCipher(OFFICIAL_EMAIL, null));
    }

    @Test
    @DisplayName("Given the overloaded encrypt(int[]), When the array is not 256 bits, Then IllegalArgumentException is thrown")
    void overloadRejectsWrongLength() {
        XorCipher cipher = new XorCipher(OFFICIAL_EMAIL);
        assertThrows(IllegalArgumentException.class, () -> cipher.encrypt(new int[64]));
        assertThrows(IllegalArgumentException.class, () -> cipher.encrypt((int[]) null));
    }
}

/* Test results (JUnit 5):
PASS  Given SecureMessenger, When I plug in either cipher, Then send/receive works without changing it
PASS  Given the spec key, When I XOR-encrypt 8 NUL bytes, Then I get KS1 + KS2 (the key itself)
PASS  Given the overloaded encrypt(int[]), When the array is not 256 bits, Then IllegalArgumentException is thrown
PASS  Given a null cipher or key generator, When I build the object, Then IllegalArgumentException is thrown
PASS  Given a ciphertext, When I decrypt with a different e-mail, Then the original is NOT recovered
PASS  Given the same message, When encrypted with HBEA and with XOR, Then the ciphertexts differ
PASS  Given my e-mail, When I encrypt with XOR and decrypt, Then I get the original back
PASS  Given an invalid message, When I send it, Then InvalidMessageException is thrown
8 tests successful, 0 failed
*/
