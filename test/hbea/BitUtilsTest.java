package hbea;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

/** Task 3 (TDD + exceptions): tests for BitUtils.xor, the conversions and the tables. */
class BitUtilsTest {

    // ---------- Task 3: XOR ----------

    @Test
    void xorKnownValues() {
        // F0 = 11110000, 3C = 00111100  ->  XOR = 11001100 = CC
        int[] result = BitUtils.xor(BitUtils.fromHex("F0"), BitUtils.fromHex("3C"));
        assertEquals("CC", BitUtils.toHex(result));
    }

    @Test
    void xorWithItselfGivesZero() {
        int[] a = BitUtils.fromHex("6C099BA0");
        assertEquals("00000000", BitUtils.toHex(BitUtils.xor(a, a)));
    }

    @Test
    void xorTwiceGivesOriginal() {
        // x XOR y XOR y = x  <- the property that makes Feistel decryption work
        int[] x = BitUtils.fromHex("4D656574");
        int[] y = BitUtils.fromHex("6B80A973");
        int[] back = BitUtils.xor(BitUtils.xor(x, y), y);
        assertArrayEquals(x, back);
    }

    @Test
    void xorDifferentLengthsThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> BitUtils.xor(new int[32], new int[48]));
    }

    @Test
    void xorNullThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> BitUtils.xor(null, new int[32]));
        assertThrows(IllegalArgumentException.class,
                () -> BitUtils.xor(new int[32], null));
    }

    // ---------- Conversions ----------

    @Test
    void bytesToBitsIsMostSignificantBitFirst() {
        // 'M' = 77 = 01001101
        int[] bits = BitUtils.bytesToBits("M".getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals(new int[]{0, 1, 0, 0, 1, 1, 0, 1}, bits);
    }

    @Test
    void bitsToBytesReversesBytesToBits() {
        byte[] original = "Meet me ".getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(original, BitUtils.bitsToBytes(BitUtils.bytesToBits(original)));
    }

    @Test
    void hexRoundTrip() {
        assertEquals("4D656574206D6520", BitUtils.toHex(BitUtils.fromHex("4D656574206D6520")));
    }

    // ---------- Section 7 test vectors (tables + permute) ----------

    @Test
    void block1MatchesTestVector() {
        int[] block = BitUtils.bytesToBits("Meet me ".getBytes(StandardCharsets.US_ASCII));
        assertEquals("4D656574206D6520", BitUtils.toHex(block));
    }

    @Test
    void initialPermutationMatchesTestVector() {
        int[] block = BitUtils.fromHex("4D656574206D6520");
        int[] x = BitUtils.permute(block, HbeaTables.ip());
        assertEquals("6F086F6700FE2100", BitUtils.toHex(x));   // L0 + R0
    }

    @Test
    void finalPermutationUndoesInitialPermutation() {
        int[] block = BitUtils.fromHex("4D656574206D6520");
        int[] back = BitUtils.permute(BitUtils.permute(block, HbeaTables.ip()), HbeaTables.fp());
        assertArrayEquals(block, back);
    }

    @Test
    void expansionOfKS1GivesRK1() {
        int[] ks1 = BitUtils.fromHex("6C099BA0");
        assertEquals("358053CF7D00", BitUtils.toHex(BitUtils.permute(ks1, HbeaTables.e())));
    }

    @Test
    void sBoxExampleFromSection44() {
        assertEquals(13, HbeaTables.sBox(0, 1, 6));   // S1[1][6] = 13 (box 0 = S1)
    }

    @Test
    void xorMatchesSection7TestVector(){
        // E(R0) XOR RK1 = 3597AFDF5500  (48-bit values from Section 7)
        int[] eR0 = BitUtils.fromHex("0017FC102800");
        int[] rk1 = BitUtils.fromHex("358053CF7D00");
        assertEquals("3597AFDF5500", BitUtils.toHex(BitUtils.xor(eR0, rk1)));
    }

    @Test
    void xorLengthErrorHasHelpfulMessage(){
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> BitUtils.xor(new int[32], new int[48]));
        assertTrue(e.getMessage().contains("same length"));
    }


    // ---------- Defensive checks: clear exceptions instead of crashes ----------

    @Test
    void conversionsRejectNull() {
        assertThrows(IllegalArgumentException.class, () -> BitUtils.toHex(null));
        assertThrows(IllegalArgumentException.class, () -> BitUtils.fromHex(null));
        assertThrows(IllegalArgumentException.class, () -> BitUtils.bytesToBits(null));
        assertThrows(IllegalArgumentException.class, () -> BitUtils.bitsToBytes(null));
        assertThrows(IllegalArgumentException.class, () -> BitUtils.permute(null, HbeaTables.e()));
    }

    @Test
    void fromHexRejectsNonHex() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> BitUtils.fromHex("4G"));
        assertTrue(e.getMessage().contains("not a hex digit"));
    }

    @Test
    void permuteRejectsTableBiggerThanInput() {
        // IP refers to positions up to 64, so it cannot be applied to 32 bits
        assertThrows(IllegalArgumentException.class, () -> BitUtils.permute(new int[32], HbeaTables.ip()));
    }

    @Test
    void wrongBitCountsRejected() {
        assertThrows(IllegalArgumentException.class, () -> BitUtils.toHex(new int[5]));
        assertThrows(IllegalArgumentException.class, () -> BitUtils.bitsToBytes(new int[7]));
    }

    @Test
    void lowerCaseHexAccepted() {
        assertEquals("ABCDEF", BitUtils.toHex(BitUtils.fromHex("abcdef")));
    }
}

/* Test results (JUnit 5):
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
