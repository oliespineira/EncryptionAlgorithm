package hbea;

/**
 * this is the contract for 'turn the seed into key material'.
 * KeyGenerator: turns a seed (the user's e-mail) into key material.
 *
 * <p>Concepts shown: interface constants. Every field declared in an interface
 * is automatically {@code public static final}, so {@code SEGMENTS} and
 * {@code SEGMENT_BITS} are shared constants, not per-object data.</p>
 */
public interface KeyGenerator {
    int SEGMENTS = 8; // interface constants are public static final
    int SEGMENT_BITS = 32;

    /**
     * @param seed the key seed (an e-mail address)
     * @return 8 key segments of 32 bits each (each value 0 or 1)
     * @throws IllegalArgumentException if the seed is null or blank
     */
    int[][] generateKeySegments(String seed); // 8 x 32 bits
}

/* Output: interface, it has no main method. See KeyGenerationDemo.java for the
   output of its implementation, Sha256KeyGenerator. */
