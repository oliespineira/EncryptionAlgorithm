package hbea;

import java.util.Arrays;

public class HbeaCipher extends AbstractBlockCipher {
    public static final int ROUNDS = 8;
    public static final int HALF_BITS = 32;

    private final RoundFunction roundFunction;
    private final int[][] roundKeys;
    private final int[][] reversedRoundKeys;

    public HbeaCipher(String email) {
        this(email, new Sha256KeyGenerator(), new DesRoundFunction());
    }

    public HbeaCipher(String email, KeyGenerator keyGenerator, RoundFunction roundFunction) {
        if (keyGenerator == null || roundFunction == null) {
            throw new IllegalArgumentException("Key generator and round function must not be null.");
        }
        this.roundFunction = roundFunction;
        int[][] segments = keyGenerator.generateKeySegments(email);
        this.roundKeys = new int[ROUNDS][];
        for (int i = 0; i < ROUNDS; i++) {
            roundKeys[i] = BitUtils.permute(segments[i], HbeaTables.e());
        }
        this.reversedRoundKeys = reverse(roundKeys);
    }

    @Override
    protected int[] encryptBlock(int[] block64) {
        return feistel(block64, roundKeys, roundFunction);
    }

    @Override
    protected int[] decryptBlock(int[] block64) {
        return feistel(block64, reversedRoundKeys, roundFunction);
    }

    @Override
    public String getName() {
        return "HBEA";
    }

    /**
     * Returns a COPY of one round key. Package-private on purpose (no "public"):
     * the key must not be visible outside the hbea package (Section 5.3).
     * Only the tests, which live in the same package, use it.
     */
    int[] roundKey(int round) {
        if (round < 1 || round > ROUNDS) {
            throw new IllegalArgumentException("Round must be between 1 and " + ROUNDS + " (got " + round + ").");
        }
        return roundKeys[round - 1].clone();
    }

    public int[][] trace(int[] block64) {
        return trace(block64, roundKeys, roundFunction);
    }

    public int[][] traceDecryption(int[] block64) {
        return trace(block64, reversedRoundKeys, roundFunction);
    }

    static int[][] trace(int[] block64, int[][] keys, RoundFunction f) {
        if (block64 == null || block64.length != BLOCK_BITS) {
            throw new IllegalArgumentException("Block must be exactly " + BLOCK_BITS + " bits.");
        }
        int[] x = BitUtils.permute(block64, HbeaTables.ip());
        int[] left = Arrays.copyOfRange(x, 0, HALF_BITS);
        int[] right = Arrays.copyOfRange(x, HALF_BITS, BLOCK_BITS);
        int[][] states = new int[keys.length + 1][];
        states[0] = join(left, right);
        for (int i = 0; i < keys.length; i++) {
            int[] newRight = BitUtils.xor(left, f.apply(right, keys[i]));
            left = right;
            right = newRight;
            states[i + 1] = join(left, right);
        }
        return states;
    }

    static int[] feistel(int[] block64, int[][] keys, RoundFunction f) {
        int[][] states = trace(block64, keys, f);
        int[] last = states[keys.length];
        int[] swapped = join(Arrays.copyOfRange(last, HALF_BITS, BLOCK_BITS), Arrays.copyOfRange(last, 0, HALF_BITS));
        return BitUtils.permute(swapped, HbeaTables.fp());
    }

    static int[][] reverse(int[][] keys) {
        int[][] reversed = new int[keys.length][];
        for (int i = 0; i < keys.length; i++) {
            reversed[i] = keys[keys.length - 1 - i];
        }
        return reversed;
    }

    private static int[] join(int[] left, int[] right) {
        int[] out = new int[left.length + right.length];
        System.arraycopy(left, 0, out, 0, left.length);
        System.arraycopy(right, 0, out, left.length, right.length);
        return out;
    }
}