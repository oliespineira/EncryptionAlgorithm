package hbea;

/**
 * BitUtils: static helpers for working with bits (Appendix B toolbox).
 *
 * <p>Bits are stored as int values 0 or 1; index 0 is the leftmost (most
 * significant) bit. The class is {@code final} with a private constructor: it is a
 * utility class that is never instantiated or extended.</p>
 *
 * <p>Every method validates its input and throws {@link IllegalArgumentException}
 * (an unchecked exception) with a clear message instead of letting a
 * NullPointerException or ArrayIndexOutOfBoundsException escape.</p>
 */
public final class BitUtils {

    /** Private constructor: nobody outside the class can write new BitUtils(). */
    private BitUtils() { }

    /**
     * Rearranges bits using a 1-based table: out[i] = in[table[i] - 1].
     * Output length = table length (so E can expand 32 to 48 bits).
     *
     * @throws IllegalArgumentException if an argument is null or a table entry is out of range
     */
    public static int[] permute(int[] input, int[] table) {
        requireNonNull(input, "permute: input");
        requireNonNull(table, "permute: table");
        int[] out = new int[table.length];
        for (int i = 0; i < table.length; i++) {
            int position = table[i];
            if (position < 1 || position > input.length) {
                throw new IllegalArgumentException("permute: table position " + position
                        + " does not exist in an input of " + input.length + " bits.");
            }
            out[i] = input[position - 1];
        }
        return out;
    }

    /**
     * Bitwise XOR of two arrays of the same length (Task 3).
     *
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
        if (bytes == null) {
            throw new IllegalArgumentException("bytesToBits: bytes must not be null.");
        }
        int[] bits = new int[bytes.length * 8];
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
        requireNonNull(bits, "bitsToBytes: bits");
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
        requireNonNull(bits, "toHex: bits");
        if (bits.length % 4 != 0) {
            throw new IllegalArgumentException("Number of bits must be a multiple of 4.");
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bits.length; i += 4) {
            int v = bits[i] * 8 + bits[i + 1] * 4 + bits[i + 2] * 2 + bits[i + 3];
            sb.append(Character.toUpperCase(Character.forDigit(v, 16)));
        }
        return sb.toString();
    }

    /**
     * Every hex digit becomes 4 bits (reverse of toHex).
     *
     * @throws IllegalArgumentException if the text is null or has a non-hex character
     */
    public static int[] fromHex(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("fromHex: text must not be null.");
        }
        int[] bits = new int[hex.length() * 4];
        for (int i = 0; i < hex.length(); i++) {
            char c = hex.charAt(i);
            if (!isHexDigit(c)) {
                throw new IllegalArgumentException("fromHex: '" + c + "' at position " + i
                        + " is not a hex digit.");
            }
            int v = Character.digit(c, 16);
            for (int k = 0; k < 4; k++) {
                bits[i * 4 + k] = (v >> (3 - k)) & 1;
            }
        }
        return bits;
    }

    /** True only for 0-9, A-F and a-f (Character.digit alone would also accept other Unicode digits). */
    public static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
    }

    private static void requireNonNull(int[] array, String what) {
        if (array == null) {
            throw new IllegalArgumentException(what + " must not be null.");
        }
    }
}

/* Output: utility class, it has no main method. See XorDemo.java for a run, and
   BitUtilsTest for its unit tests:
PASS  xorTwiceGivesOriginal()
PASS  initialPermutationMatchesTestVector()
PASS  expansionOfKS1GivesRK1()
PASS  xorDifferentLengthsThrows()
PASS  xorLengthErrorHasHelpfulMessage()
PASS  permuteRejectsTableBiggerThanInput()
PASS  hexRoundTrip()
PASS  bitsToBytesReversesBytesToBits()
PASS  xorMatchesSection7TestVector()
PASS  lowerCaseHexAccepted()
PASS  finalPermutationUndoesInitialPermutation()
PASS  xorKnownValues()
PASS  wrongBitCountsRejected()
PASS  block1MatchesTestVector()
PASS  bytesToBitsIsMostSignificantBitFirst()
PASS  xorNullThrows()
PASS  fromHexRejectsNonHex()
PASS  sBoxExampleFromSection44()
PASS  xorWithItselfGivesZero()
PASS  conversionsRejectNull()
20 tests successful, 0 failed
*/
