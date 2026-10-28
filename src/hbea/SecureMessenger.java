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

    /** Encrypts a message before "sending" it. Returns 64 hex digits. */
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