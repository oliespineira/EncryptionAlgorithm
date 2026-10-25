package hbea;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

/** TDD tests for BitUtils (Task 3: XOR + exceptions) and the tables. */
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

}