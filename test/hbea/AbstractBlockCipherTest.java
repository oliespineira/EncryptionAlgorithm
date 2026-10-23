package hbea;

public abstract class AbstractBlockCipherTest implements Cipher {
    /*    String encrypt(String plaintext) throws InvalidMessageException; // 64 hex digits
        String decrypt(String cipherHex);
        String getName();

        // default method: every cipher gets a self-check for free
        default boolean verifyRoundTrip(String plaintext) throws InvalidMessageException {
            return plaintext.equals(decrypt(encrypt(plaintext)));

        }
    */
    //these are specified in section 4.3
    protected static final int MESSAGE_LENGTH = 32;

    protected static final char PAD_CHAR = '\0';

    protected static void validate(String message) throws InvalidMessageException {
        if (message == null) {
            throw new InvalidMessageException("Message must not be null"); // the order really matters here since if we called .isEmpty on null there would be a NullPointerException and program would crash.
        }
        if (message.isEmpty()) {
            throw new InvalidMessageException("Message must not be empty");

        }
        if (message.length() > MESSAGE_LENGTH) {
            throw new InvalidMessageException("Message must be at most" + MESSAGE_LENGTH
                    + " characters (got " + message.length() + ").");
        }
        for (int i = 0; i < message.length(); i++) {// here we look at subsection 1 where it says we must have characters between codes 32 and 126
            char ch = message.charAt(i);
            if (ch < 32 || ch > 126) {
                throw new InvalidMessageException("Invalid character '" + ch
                        + "' at position " + i + ": only printable ASCII (32-126) is allowed.");
            }
        }


    }

    // here we pad messages with Null characters until it is exactly 32 characters

    protected static String pad(String message){
        StringBuilder sb = new StringBuilder(message);
        while(sb.length()< MESSAGE_LENGTH){
            sb.append(PAD_CHAR);
        }
        return sb.toString();
    }

    //these are the steps all subclasses must provide (fill in later)

    protected abstract int[] encryptBlock(int[] block64);
    protected abstract int[] decryptBlock(int[] block64);
}
