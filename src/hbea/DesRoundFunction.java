package hbea;

/**
 * The DES-style round function (Section 4.4):
 * F(R, RK) = P( S( E(R) XOR RK ) )
 */
public class DesRoundFunction implements RoundFunction {

    @Override
    public int[] apply(int[] right32, int[] roundKey48) {
        /*This is the round function F. iT takes half of the block (32 bits) and a round key(48 bits) and produces 32 scrambled bits
        *  doesnt do any work by itsef it just runs three methods in a chain, like an assembly line.*/
        int[] expanded = expand(right32);                       // 32 -> 48
        int[] mixed = BitUtils.xor(expanded, roundKey48);       // 48
        int[] substituted = substitute(mixed);                  // 48 -> 32
        return permute(substituted);                            // 32
    }

    /** E: expand 32 bits to 48 bits with the Expansion table.
     * this is needed because the round key is 48 bits and XOR only works on arrays of the same length. so we have to make sure that r is transformed from 32 bits to 48
     * */
    public int[] expand(int[] right32) {
        return BitUtils.permute(right32, HbeaTables.e());// here bits just change places.
    }

    /** S: 8 groups of 6 bits, each through its S-box, giving 8 x 4 = 32 bits. */
    public int[] substitute(int[] bits48) {
        int[] out = new int[32];// making room for the result
        for (int box = 0; box < 8; box++) {// running for the 8 groups
            int start = box * 6;// each group is 6 bits long, so we multiply by 6 to make enough space. (block zero will have from 0 to 5 and so on.)
            int b1 = bits48[start],     b2 = bits48[start + 1], b3 = bits48[start + 2];
            int b4 = bits48[start + 3], b5 = bits48[start + 4], b6 = bits48[start + 5]; // reading the 6 bits from this group

            int row = b1 * 2 + b6;                        // outer bits b1 b6   -> 0..3. this is necessary because the first and last bits together choose the row and 2 bits can make 4 numbers.
            int col = b2 * 8 + b3 * 4 + b4 * 2 + b5;      // inner bits b2..b5  -> 0..15. these choose the column.

            int value = HbeaTables.sBox(box, row, col);// here we look at the lookup table and check which number is there

            for (int k = 0; k < 4; k++) { // write value as 4 bits, MSB first. turns number back nto binary, one bit at a time.
                out[box * 4 + k] = (value >> (3 - k)) & 1;
            }
        }
        return out;
    }

    /** P: permute 32 bits with the Permutation table. */
    public int[] permute(int[] bits32) {
        return BitUtils.permute(bits32, HbeaTables.p());
    }


    /*
    6 bits in:     0  0 1 1 0  1
               │  └──┬───┘  │
               │   column   │
               └──── row ───┘

        row    = 0 1     = 1
        column = 0110    = 6
        S1[1][6]         = 13
        13 in 4 bits     = 1 1 0 1     ← 4 bits out
     */
}