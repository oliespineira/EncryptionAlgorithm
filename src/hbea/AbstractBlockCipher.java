package hbea;

import java.nio.charset.StandardCharsets;

/**
 * basically does all the work and leaves the actual scrambling to its subclasses.
 * AbstractBlockCipher: the shared "template" for every block cipher in the project.
 *
 * It does all the work that is the same for every algorithm (Section 4.3):
 * validation, padding with NUL, splitting into four 64-bit blocks and hex
 * conversion. The one step that differs, what happens to a single block, is left
 * to subclasses through the abstract methods {@link #encryptBlock(int[])} and
 * {@link #decryptBlock(int[])}. This is the <b>template method</b> pattern.</p>
 *
 * <p>Concepts shown: abstract class implementing an interface, abstract methods,
 * {@code final} methods that subclasses cannot override, method
 * <b>overloading</b> ({@code encrypt(String)} and {@code encrypt(int[])}),
 * {@code throw}/{@code throws} with a checked and an unchecked exception.</p>
 */
public abstract class AbstractBlockCipher implements Cipher {

    // Constants (extracted from Section 4.3)

    // Every message is padded to exactly 32 characters = 256 bits.
    protected static final int MESSAGE_LENGTH = 32;
    // NUL never appears in valid input, so it can be removed safely after decryption.
    protected static final char PAD_CHAR = '\0';
    // Lowest and highest printable ASCII codes accepted.
    private static final int MIN_PRINTABLE = 32;
    private static final int MAX_PRINTABLE = 126;

    public static final int BLOCK_BITS = 64;
    public static final int BLOCK_COUNT = MESSAGE_LENGTH * 8 / BLOCK_BITS;   // 4
    public static final int CIPHER_HEX_LENGTH = MESSAGE_LENGTH * 2;          // 64

    // The steps every subclass must provide

    /** Encrypts one 64-bit block. */
    protected abstract int[] encryptBlock(int[] block64);

    /** Decrypts one 64-bit block. */
    protected abstract int[] decryptBlock(int[] block64);

    // template methods

    /**
     * Encrypts a text message: validate, pad to 32 characters, turn it into 256
     * bits, then hand the bits to the overloaded {@link #encrypt(int[])}.
     *
     * @throws InvalidMessageException if the message breaks a rule of Section 4.3
     */
    @Override
    public final String encrypt(String plaintext) throws InvalidMessageException {
        String message = prepare(plaintext);
        int[] bits256 = BitUtils.bytesToBits(message.getBytes(StandardCharsets.US_ASCII));
        return encrypt(bits256);
    }

    /**
     * OVERLOADED version of encrypt: same name, different parameter type.
     * Works directly on 256 bits that are already prepared.
     *
     * @param bits256 exactly 256 bits (each 0 or 1)
     * @return the ciphertext as 64 uppercase hex digits
     * @throws IllegalArgumentException if the array is null or not 256 bits long
     */
    public final String encrypt(int[] bits256) {
        if (bits256 == null || bits256.length != BLOCK_COUNT * BLOCK_BITS) {
            throw new IllegalArgumentException("Expected exactly " + (BLOCK_COUNT * BLOCK_BITS) + " bits.");
        }
        StringBuilder hex = new StringBuilder();
        for (int b = 0; b < BLOCK_COUNT; b++) {
            int[] block = new int[BLOCK_BITS];
            System.arraycopy(bits256, b * BLOCK_BITS, block, 0, BLOCK_BITS);
            hex.append(BitUtils.toHex(encryptBlock(block)));
        }
        return hex.toString();
    }

    /**
     * Decrypts 64 hex digits: split into 4 blocks, decrypt each, join, remove padding.
     *
     * @throws IllegalArgumentException if the ciphertext is not 64 hex digits
     */
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

    // Step 2 helpers: validation and padding (Task 1, TDD)

    /**
     * Checks the rules of Section 4.3. The order matters: the null check must come
     * first, otherwise {@code message.isEmpty()} would throw a NullPointerException.
     *
     * @throws InvalidMessageException with a message that explains the problem
     */
    protected static void validate(String message) throws InvalidMessageException {
        if (message == null) {
            throw new InvalidMessageException("Message must not be null.");
        }
        if (message.isEmpty()) {
            throw new InvalidMessageException("Message must not be empty.");
        }
        if (message.length() > MESSAGE_LENGTH) {
            throw new InvalidMessageException("Message must be at most " + MESSAGE_LENGTH
                    + " characters (got " + message.length() + ").");
        }
        for (int i = 0; i < message.length(); i++) {
            char ch = message.charAt(i);
            if (ch < MIN_PRINTABLE || ch > MAX_PRINTABLE) {
                throw new InvalidMessageException("Invalid character '" + ch + "' (code " + (int) ch
                        + ") at position " + i + ": only printable ASCII (32-126) is allowed.");
            }
        }
    }

    /** Pads a message with NUL characters until it has exactly 32 characters. */
    protected static String pad(String message) {
        StringBuilder sb = new StringBuilder(message);
        while (sb.length() < MESSAGE_LENGTH) {
            sb.append(PAD_CHAR);
        }
        return sb.toString();
    }

    /**
     * Validates and then pads. A short message is perfectly valid, so padding is
     * normal behaviour, not an error: only a message that breaks a rule throws.
     *
     * @return a valid message of exactly 32 characters
     * @throws InvalidMessageException if the message is invalid (it is never padded)
     */
    public static String prepare(String message) throws InvalidMessageException {
        validate(message);
        return pad(message);
    }

    /** Removes only the trailing NUL padding; spaces the user typed are kept. */
    public static String unpad(String message) {
        int end = message.length();
        while (end > 0 && message.charAt(end - 1) == PAD_CHAR) {
            end--;
        }
        return message.substring(0, end);
    }

    // Splitting into 64-bit blocks

    /** Splits a 32-character message into 4 blocks of 64 bits. */
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

    /** Joins 4 blocks of 64 bits back into 32 characters (reverse of toBlocks). */
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

    /**
     * Checks that a ciphertext is exactly 64 hexadecimal digits (0-9, A-F, a-f).
     *
     * @throws IllegalArgumentException if it is null, the wrong length, or not hex
     */
    public static void validateCipherHex(String cipherHex) {
        if (cipherHex == null || cipherHex.length() != CIPHER_HEX_LENGTH) {
            throw new IllegalArgumentException("Ciphertext must be exactly " + CIPHER_HEX_LENGTH + " hex digits.");
        }
        for (int i = 0; i < cipherHex.length(); i++) {
            if (!BitUtils.isHexDigit(cipherHex.charAt(i))) {
                throw new IllegalArgumentException("Invalid hex digit '" + cipherHex.charAt(i)
                        + "' at position " + i + ".");
            }
        }
    }
}

/* Output: abstract class, it cannot be instantiated or run on its own. Its tests
   (AbstractBlockCipherTest, using a small IdentityCipher subclass) pass:
PASS  Whole pipeline (with the identity test cipher) > A short message survives encrypt + decrypt with the padding removed
PASS  Whole pipeline (with the identity test cipher) > encrypt rejects an invalid message, decrypt rejects an invalid ciphertext
PASS  Whole pipeline (with the identity test cipher) > verifyRoundTrip (default method of Cipher) returns true
PASS  Whole pipeline (with the identity test cipher) > encrypt returns 64 hex digits
PASS  Ciphertext format (64 hex digits) > Unicode digits that are not 0-9/A-F are rejected (e.g. Arabic-Indic three)
PASS  Ciphertext format (64 hex digits) > Lower-case hex is accepted
PASS  Ciphertext format (64 hex digits) > A ciphertext with the wrong length is rejected
PASS  Ciphertext format (64 hex digits) > A ciphertext with a non-hex character is rejected
PASS  Ciphertext format (64 hex digits) > 64 hex digits are accepted
PASS  Segmentation into 4 blocks of 64 bits > Block 1 of "Meet me ..." is 4D656574206D6520 (spec test vector)
PASS  Segmentation into 4 blocks of 64 bits > fromBlocks(toBlocks(m)) gives back m
PASS  Segmentation into 4 blocks of 64 bits > Splitting a message that is not 32 characters is rejected
PASS  Segmentation into 4 blocks of 64 bits > A 32-character message becomes 4 blocks of 64 bits
PASS  Padding and unpadding > unpad keeps spaces the user typed (only the padding character is removed)
PASS  Padding and unpadding > unpad(pad(x)) gives back x
PASS  Padding and unpadding > pad does not change a message that already has 32 characters
PASS  Short messages are valid and get padded > prepare() leaves a 32-character message unchanged (no padding)
PASS  Short messages are valid and get padded > A message shorter than 32 characters is valid (no exception)
PASS  Short messages are valid and get padded > prepare() pads a short message to 32 characters with NUL
PASS  Short messages are valid and get padded > prepare() does not pad an invalid message: the error reaches the caller
PASS  Short messages are valid and get padded > A 1-character message is accepted and padded with 31 NULs
PASS  Validation of the input message > The boundary characters space (32) and ~ (126) are accepted
PASS  Validation of the input message > A message with a non-printable or non-ASCII character is rejected > "café"
PASS  Validation of the input message > A message with a non-printable or non-ASCII character is rejected > "año"
PASS  Validation of the input message > A message with a non-printable or non-ASCII character is rejected > "tab	here"
PASS  Validation of the input message > A message with a non-printable or non-ASCII character is rejected > "smile ☺"
PASS  Validation of the input message > A message with a non-printable or non-ASCII character is rejected > "nul\u0000inside"
PASS  Validation of the input message > A message with a non-printable or non-ASCII character is rejected > "del\u007f"
PASS  Validation of the input message > An empty message is rejected
PASS  Validation of the input message > A message longer than 32 characters is rejected
PASS  Validation of the input message > A message of 33 characters (one too many) is rejected
PASS  Validation of the input message > A null message is rejected
PASS  Validation of the input message > A message of exactly 32 printable characters is accepted
33 tests successful, 0 failed
*/
