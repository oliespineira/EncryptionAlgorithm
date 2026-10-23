public interface Cipher {
    String encrypt(String plaintext) throws InvalidMessageException; // 64 hex digits
    String decrypt(String cipherHex);
    String getName();

    // default method: every cipher gets a self-check for free
    default boolean verifyRoundTrip(String plaintext) throws InvalidMessageException {
        return plaintext.equals(decrypt(encrypt(plaintext)));

    }
}

