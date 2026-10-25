package hbea;

import java.nio.charset.StandardCharsets;

public abstract class AbstractBlockCipher implements Cipher {
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

    public static final int BLOCK_BITS = 64;
    public static final int BLOCK_COUNT = MESSAGE_LENGTH * 8 / BLOCK_BITS;
    public static final int CIPHER_HEX_LENGTH = MESSAGE_LENGTH * 2;

    @Override
    public final String encrypt(String plaintext) throws InvalidMessageException {
        String message = prepare(plaintext);
        int[][] blocks = toBlocks(message);
        StringBuilder hex = new StringBuilder();
        for (int[] block : blocks) {
            hex.append(BitUtils.toHex(encryptBlock(block)));
        }
        return hex.toString();
    }

    @Override
    public final String decrypt(String cipherHex) {
        validateCipherHex(cipherHex);
        int[] allBits = BitUtils.fromHex(cipherHex);
        int[][] blocks = new int[BLOCK_COUNT][];
        for (int b = 0; b < BLOCK_COUNT; b++) {
            int[] block = new int[BLOCK_BITS];
            System.arraycopy(allBits, b * BLOCK_BITS, block, 0, BLOCK_BITS);
            blocks[b] = decryptBlock(block);
        }
        return unpad(fromBlocks(blocks));
    }

    public static void requireFullLength(String message) throws MessageTooShortException {
        if (message.length() < MESSAGE_LENGTH) {
            throw new MessageTooShortException(message.length(), MESSAGE_LENGTH);
        }
    }

    public static String prepare(String message) throws InvalidMessageException {
        validate(message);
        try {
            requireFullLength(message);
            return message;
        } catch (MessageTooShortException e) {
            System.out.println("Notice: " + e.getMessage());
            return pad(message);
        }
    }

    public static String unpad(String message) {
        int end = message.length();
        while (end > 0 && message.charAt(end - 1) == PAD_CHAR) {
            end--;
        }
        return message.substring(0, end);
    }

    public static int[][] toBlocks(String message32) {
        if (message32 == null || message32.length() != MESSAGE_LENGTH) {
            throw new IllegalArgumentException("Message must be exactly " + MESSAGE_LENGTH + " characters.");
        }
        int[] allBits = BitUtils.bytesToBits(message32.getBytes(StandardCharsets.US_ASCII));
        int[][] blocks = new int[BLOCK_COUNT][BLOCK_BITS];
        for (int b = 0; b < BLOCK_COUNT; b++) {
            System.arraycopy(allBits, b * BLOCK_BITS, blocks[b], 0, BLOCK_BITS);
        }
        return blocks;
    }

    public static String fromBlocks(int[][] blocks) {
        if (blocks == null || blocks.length != BLOCK_COUNT) {
            throw new IllegalArgumentException("Expected " + BLOCK_COUNT + " blocks.");
        }
        int[] allBits = new int[BLOCK_COUNT * BLOCK_BITS];
        for (int b = 0; b < BLOCK_COUNT; b++) {
            if (blocks[b] == null || blocks[b].length != BLOCK_BITS) {
                throw new IllegalArgumentException("Every block must have " + BLOCK_BITS + " bits.");
            }
            System.arraycopy(blocks[b], 0, allBits, b * BLOCK_BITS, BLOCK_BITS);
        }
        return new String(BitUtils.bitsToBytes(allBits), StandardCharsets.US_ASCII);
    }

    public static void validateCipherHex(String cipherHex) {
        if (cipherHex == null || cipherHex.length() != CIPHER_HEX_LENGTH) {
            throw new IllegalArgumentException("Ciphertext must be exactly " + CIPHER_HEX_LENGTH + " hex digits.");
        }
        for (int i = 0; i < cipherHex.length(); i++) {
            if (Character.digit(cipherHex.charAt(i), 16) < 0) {
                throw new IllegalArgumentException("Invalid hex digit '" + cipherHex.charAt(i)
                        + "' at position " + i + ".");
            }
        }
    }
}