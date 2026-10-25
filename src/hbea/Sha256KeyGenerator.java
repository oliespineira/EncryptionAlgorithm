package hbea;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Step 1 of HBEA (Section 4.2): seed -> SHA-256 -> 8 key segments of 32 bits.
 */
public class Sha256KeyGenerator implements KeyGenerator {

    @Override
    public int[][] generateKeySegments(String seed) {
        // 1. Normalise the seed: trim spaces + lower case
        String normalised = seed.trim().toLowerCase();

        // 2. SHA-256 of its UTF-8 bytes -> 32 bytes = 256 bits
        byte[] hash;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            hash = md.digest(normalised.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
        int[] keyBits = BitUtils.bytesToBits(hash);

        // 3. Split into 8 consecutive slices of 32 bits (KS1 = first 32 bits)
        int[][] segments = new int[SEGMENTS][];
        for (int i = 0; i < SEGMENTS; i++) {
            segments[i] = Arrays.copyOfRange(keyBits, i * SEGMENT_BITS, (i + 1) * SEGMENT_BITS);
        }
        return segments;
    }
}