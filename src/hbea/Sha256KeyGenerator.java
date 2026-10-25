package hbea;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Task 2 - Key generation.
 *
 * Turns a seed (the user's official email) into the 256-bit HBEA key:
 *   1. seed  -> bytes (UTF-8)
 *   2. bytes -> SHA-256 digest (32 bytes = 256 bits)
 *   3. 256 bits -> 8 key segments of 32 bits each (KS1 ... KS8)
 *
 * The result is returned as int[8][32], where every value is 0 or 1 and
 * index 0 is the most significant (leftmost) bit, the same bit format
 * BitUtils and RoundFunction use.
 *
 * Security notes ("store the generated keys securely"):
 *   - The class is stateless: it never keeps a key in a field, so there is
 *     nothing left in memory to leak after a call returns.
 *   - Every call returns a fresh array, so one caller cannot change the
 *     key another caller is using.
 *   - The intermediate digest is wiped as soon as it has been converted to bits.
 *   - wipe() lets the caller erase a key once it is no longer needed.
 */
public class Sha256KeyGenerator implements KeyGenerator {

    /** Name of the hash algorithm, as java.security expects it. */
    private static final String ALGORITHM = "SHA-256";

    /** Total key length in bits: 8 segments x 32 bits = 256. */
    public static final int KEY_BITS = SEGMENTS * SEGMENT_BITS;

    /**
     * Generates the 8 key segments from a text seed (normally an email).
     *
     * @param seed the user's email; must not be null, empty or only spaces
     * @return int[8][32] with the key segments KS1..KS8
     * @throws IllegalArgumentException if the seed is null or blank
     */
    @Override
    public int[][] generateKeySegments(String seed) {
        if (seed == null) {
            throw new IllegalArgumentException("Key seed must not be null.");
        }
        if (seed.isBlank()) {
            throw new IllegalArgumentException("Key seed must not be empty or only whitespace.");
        }
        return generateKeySegments(seed.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Overload: generates the key segments from raw bytes instead of a String.
     * The String version converts to UTF-8 and delegates here, so both always
     * agree for the same input.
     *
     * @param seedBytes the seed as bytes; must not be null or empty
     * @return int[8][32] with the key segments KS1..KS8
     * @throws IllegalArgumentException if the bytes are null or empty
     */
    public int[][] generateKeySegments(byte[] seedBytes) {
        if (seedBytes == null || seedBytes.length == 0) {
            throw new IllegalArgumentException("Key seed bytes must not be null or empty.");
        }
        byte[] digest = sha256(seedBytes);           // 32 bytes
        int[] keyBits = BitUtils.bytesToBits(digest); // 256 bits, MSB first
        Arrays.fill(digest, (byte) 0);               // wipe the intermediate digest
        int[][] segments = segment(keyBits);
        Arrays.fill(keyBits, 0);                     // wipe the flat copy too
        return segments;
    }

    /**
     * Computes the SHA-256 digest of the given bytes.
     * Every Java platform is required to support SHA-256, so the checked
     * NoSuchAlgorithmException should never happen; if it does, the JVM is
     * broken and we fail loudly instead of continuing without a key.
     */
    static byte[] sha256(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(ALGORITHM);
            return md.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(ALGORITHM + " is not available on this Java platform.", e);
        }
    }

    /**
     * Splits a 256-bit key into 8 consecutive 32-bit segments:
     * KS1 = bits 0..31, KS2 = bits 32..63, ..., KS8 = bits 224..255.
     *
     * @throws IllegalArgumentException if the input is not exactly 256 bits
     */
    static int[][] segment(int[] keyBits) {
        if (keyBits == null || keyBits.length != KEY_BITS) {
            throw new IllegalArgumentException("Key must be exactly " + KEY_BITS + " bits.");
        }
        int[][] segments = new int[SEGMENTS][SEGMENT_BITS];
        for (int s = 0; s < SEGMENTS; s++) {
            System.arraycopy(keyBits, s * SEGMENT_BITS, segments[s], 0, SEGMENT_BITS);
        }
        return segments;
    }

    /**
     * Overwrites every bit of a key with 0, so the key does not stay in memory
     * after it has been used. Safe to call with null.
     */
    public static void wipe(int[][] segments) {
        if (segments == null) {
            return;
        }
        for (int[] segment : segments) {
            if (segment != null) {
                Arrays.fill(segment, 0);
            }
        }
    }
}