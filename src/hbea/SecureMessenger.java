package hbea;

/**
 * SecureMessenger: the "application" part of the project (Section 5.2).
 *
 * It only knows the Cipher INTERFACE, never a concrete class like HbeaCipher
 * or XorCipher. This is "programming to an interface": any object that
 * implements Cipher can be passed in, and this class never has to change.
 */
public class SecureMessenger {

    /** The cipher in use. Its type is the interface, not a class. */
    private final Cipher cipher;

    public SecureMessenger(Cipher cipher) {
        if (cipher == null) {
            throw new IllegalArgumentException("Cipher must not be null.");
        }
        this.cipher = cipher;
    }

    /**
     * Encrypts a message before "sending" it.
     *
     * @return 64 hex digits
     * @throws InvalidMessageException passed on (not caught here) so the caller,
     *                                 who talks to the user, decides what to do
     */
    public String send(String message) throws InvalidMessageException {
        return cipher.encrypt(message);
    }

    /** Decrypts a received ciphertext back into the original message. */
    public String receive(String cipherHex) {
        return cipher.decrypt(cipherHex);
    }

    /** Name of the cipher being used (HBEA, XOR, ...). */
    public String getCipherName() {
        return cipher.getName();
    }

    /** Uses the interface's default method: encrypt + decrypt gives the original. */
    public boolean selfCheck(String message) throws InvalidMessageException {
        return cipher.verifyRoundTrip(message);
    }
}

/* Output: no main method; it is exercised by the tests and demos.
SecureMessenger used with both ciphers (from Main):
=== Cipher: HBEA ===
Plaintext:  Meet me at the library at 5pm!!!
Ciphertext: 9F61A7606FAF6716DA9C2E64EEEEC4D0C43AC1100095F67B4081A8FE511AE46D
Decrypted:  Meet me at the library at 5pm!!!
Round trip: OK

=== Cipher: XOR ===
Plaintext:  Meet me at the library at 5pm!!!
Ciphertext: 9A72D019F7EC0C25B6639519BFE44969BE75C70CA5F84964A337801DBAA04824
Decrypted:  Meet me at the library at 5pm!!!
Round trip: OK
*/
