package hbea;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** TDD unit tests for Task 4: E, S-boxes, P and F, checked against Section 7. */
class DesRoundFunctionTest {

    private final DesRoundFunction f = new DesRoundFunction();

    // Values from Section 7
    private static final String L0  = "6F086F67";
    private static final String R0  = "00FE2100";
    private static final String RK1 = "358053CF7D00";

    @Test
    void expansionOfR0() {
        int[] result = f.expand(BitUtils.fromHex(R0));
        assertEquals(48, result.length);
        assertEquals("0017FC102800", BitUtils.toHex(result));
    }

    @Test
    void sBoxOutput() {
        int[] result = f.substitute(BitUtils.fromHex("3597AFDF5500"));   // E(R0) XOR RK1
        assertEquals(32, result.length);
        assertEquals("D688919D", BitUtils.toHex(result));
    }

    @Test
    void sBoxSingleLookupExample() {
        // Section 4.4: 001101 -> row 1, column 6 -> S1[1][6] = 13 = 1101
        int[] input = new int[48];                 // all zeros...
        int[] first6 = {0, 0, 1, 1, 0, 1};
        System.arraycopy(first6, 0, input, 0, 6);  // ...except the first group
        int[] result = f.substitute(input);
        assertArrayEquals(new int[]{1, 1, 0, 1}, java.util.Arrays.copyOfRange(result, 0, 4));
    }

    @Test
    void permutationP() {
        assertEquals("6B80A973", BitUtils.toHex(f.permute(BitUtils.fromHex("D688919D"))));
    }

    @Test
    void fullRoundFunctionF() {
        int[] result = f.apply(BitUtils.fromHex(R0), BitUtils.fromHex(RK1));
        assertEquals("6B80A973", BitUtils.toHex(result));
    }

    @Test
    void oneFullRound() {
        // L1 = R0 and R1 = L0 XOR F(R0, RK1)
        int[] left0 = BitUtils.fromHex(L0);
        int[] right0 = BitUtils.fromHex(R0);

        int[] left1 = right0;
        int[] right1 = BitUtils.xor(left0, f.apply(right0, BitUtils.fromHex(RK1)));

        assertEquals("00FE2100", BitUtils.toHex(left1));
        assertEquals("0488C614", BitUtils.toHex(right1));
    }
}