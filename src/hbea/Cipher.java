package hbea;

/**
 * Cipher: the contract every encryption algorithm in the project must follow.
 *
 * <p>The application ({@link SecureMessenger}, {@link Main}) only ever uses this
 * type, never a concrete class. That is "programming to an interface": a new
 * algorithm can be plugged in without touching the application code.</p>
 *
 * <p>Concepts shown: interface with abstract methods, a <b>default</b> method,
 * and a checked exception in a method signature ({@code throws}).</p>
 */
public interface Cipher {

    /**
     * Encrypts a message of 1 to 32 printable ASCII characters.
     *
     * @param plaintext the message to encrypt
     * @return the ciphertext as 64 uppercase hexadecimal digits
     * @throws InvalidMessageException if the message is null, empty, too long
     *                                 or contains a non-printable character
     */
    String encrypt(String plaintext) throws InvalidMessageException; // 64 hex digits

    /**
     * Decrypts 64 hexadecimal digits back into the original message.
     *
     * @param cipherHex the ciphertext produced by {@link #encrypt(String)}
     * @return the original message, without padding
     * @throws IllegalArgumentException if the ciphertext is not 64 hex digits
     */
    String decrypt(String cipherHex);

    /** @return a short display name for the algorithm (e.g. "HBEA"). */
    String getName();

    /**
     * Default method: every cipher gets a self-check for free.
     * Implementing classes inherit it without writing any code.
     *
     * @param plaintext the message to test
     * @return true if decrypt(encrypt(m)) gives m back
     * @throws InvalidMessageException if the message is invalid
     */
    default boolean verifyRoundTrip(String plaintext) throws InvalidMessageException {
        return plaintext.equals(decrypt(encrypt(plaintext)));
    }
}

/* Output: interface, it has no main method. It is exercised by every test class
   (e.g. HbeaCipherTest "HbeaCipher can be used through the Cipher interface") and
   by Main, whose output is pasted at the end of Main.java. */
