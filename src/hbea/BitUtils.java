package hbea;

/**
 * Utility class with static helpers for working with bits.
 * Bits are stored as int values 0 or 1; index 0 = leftmost (most significant) bit.
 */
public final class BitUtils {

    /** Private constructor: this class is never instantiated and nobody outside the class can write  new Bitutils()*/
    private BitUtils() { }

    /**
     * Rearranges bits using a 1-based table: out[i] = in[table[i] - 1].
     * Output length = table length (so E can expand 32 -> 48).
     */
    public static int[] permute(int[] input, int[] table) {
        int[] out = new int[table.length];
        for (int i = 0; i < table.length; i++) {
            out[i] = input[table[i] - 1];
        }
        return out;
    }

    /**
     * Bitwise XOR of two arrays of the same length.
     * @throws IllegalArgumentException if either array is null or lengths differ
     */
    public static int[] xor(int[] a, int[] b) {
        if (a == null || b == null) {
            throw new IllegalArgumentException("xor: arrays must not be null.");
        }
        if (a.length != b.length) {
            throw new IllegalArgumentException("xor: arrays must have the same length ("
                    + a.length + " vs " + b.length + ").");
        }
        int[] out = new int[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = a[i] ^ b[i];
        }
        return out;
    }

    /** Each byte becomes 8 bits, most significant bit first. */
    public static int[] bytesToBits(byte[] bytes) {
        int[] bits = new int[bytes.length * 8]; // each byte carries 8 bits so 8*8 is 64.
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;               // make the byte unsigned (0..255)
            for (int k = 0; k < 8; k++) {
                bits[i * 8 + k] = (v >> (7 - k)) & 1;
            }
        }
        return bits;
    }

    /** Every 8 bits become one byte (reverse of bytesToBits). */
    public static byte[] bitsToBytes(int[] bits) {
        if (bits.length % 8 != 0) {
            throw new IllegalArgumentException("Number of bits must be a multiple of 8.");
        }
        byte[] bytes = new byte[bits.length / 8];
        for (int i = 0; i < bytes.length; i++) {
            int v = 0;
            for (int k = 0; k < 8; k++) {
                v = (v << 1) | bits[i * 8 + k];     // shift left, add the next bit
            }
            bytes[i] = (byte) v;
        }
        return bytes;
    }

    /** Every 4 bits become one uppercase hex digit. */
    public static String toHex(int[] bits) {
        if (bits.length % 4 != 0) {
            throw new IllegalArgumentException("Number of bits must be a multiple of 4.");
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bits.length; i += 4) {
            int v = bits[i] * 8 + bits[i + 1] * 4 + bits[i + 2] * 2 + bits[i + 3];
            sb.append(Integer.toHexString(v).toUpperCase());
        }
        return sb.toString();
    }

    /** Every hex digit becomes 4 bits (reverse of toHex). */
    public static int[] fromHex(String hex) {
        int[] bits = new int[hex.length() * 4];
        for (int i = 0; i < hex.length(); i++) {
            int v = Integer.parseInt(String.valueOf(hex.charAt(i)), 16);
            for (int k = 0; k < 4; k++) {
                bits[i * 4 + k] = (v >> (3 - k)) & 1;
            }
        }
        return bits;
    }
}
