package hbea;

import java.util.Arrays;

/**
 * HbeaCipher: the Hybrid Block Encryption Algorithm (Sections 4.2 to 4.5).
 *
 * <p>For each 64-bit block: IP, 8 Feistel rounds, swap, IP<sup>-1</sup>.
 * Decryption runs exactly the same procedure with the round keys in reverse
 * order, which works even though F (the S-boxes) cannot be inverted.</p>
 *
 * <p>Concepts shown: inheritance ({@code extends AbstractBlockCipher}),
 * overriding the abstract methods with {@code @Override}, composition through
 * interfaces (it receives a {@link KeyGenerator} and a {@link RoundFunction}),
 * constructor overloading and chaining with {@code this(...)}, and
 * encapsulation: the round keys are {@code private final} and no public method
 * returns them.</p>
 */
public class HbeaCipher extends AbstractBlockCipher {
    public static final int ROUNDS = 8;
    public static final int HALF_BITS = 32;

    private final RoundFunction roundFunction;
    private final int[][] roundKeys;
    private final int[][] reversedRoundKeys;

    /**
     * Builds HBEA with the standard parts: SHA-256 keys and the DES round function.
     *
     * @param email the key seed
     * @throws IllegalArgumentException if the e-mail is null or blank
     */
    public HbeaCipher(String email) {
        this(email, new Sha256KeyGenerator(), new DesRoundFunction());
    }

    /**
     * Overloaded constructor: any KeyGenerator and RoundFunction can be plugged in.
     *
     * @throws IllegalArgumentException if a part is null or the generator returns
     *                                  key segments of the wrong shape
     */
    public HbeaCipher(String email, KeyGenerator keyGenerator, RoundFunction roundFunction) {
        if (keyGenerator == null || roundFunction == null) {
            throw new IllegalArgumentException("Key generator and round function must not be null.");
        }
        this.roundFunction = roundFunction;
        int[][] segments = keyGenerator.generateKeySegments(email);
        if (segments == null || segments.length < ROUNDS) {
            throw new IllegalArgumentException("The key generator must return " + ROUNDS + " key segments.");
        }
        this.roundKeys = new int[ROUNDS][];
        for (int i = 0; i < ROUNDS; i++) {
            if (segments[i] == null || segments[i].length != KeyGenerator.SEGMENT_BITS) {
                throw new IllegalArgumentException("Key segment " + (i + 1) + " must have "
                        + KeyGenerator.SEGMENT_BITS + " bits.");
            }
            roundKeys[i] = BitUtils.permute(segments[i], HbeaTables.e());   // RK(i) = E(KS(i)), 48 bits
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

    /**
     * Returns the (L, R) state after IP and after each of the 8 encryption rounds,
     * for the Task 4 demo. Package-private: only demos and tests in this package
     * can use it, so the public API of the cipher stays encrypt/decrypt/getName.
     */
    int[][] trace(int[] block64) {
        return trace(block64, roundKeys, roundFunction);
    }

    /** Same as {@link #trace(int[])} but with the round keys in reverse order (decryption). */
    int[][] traceDecryption(int[] block64) {
        return trace(block64, reversedRoundKeys, roundFunction);
    }

    /** Runs IP and the Feistel rounds, keeping a copy of every state. */
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

    /** One full block: IP, rounds, swap (R8 + L8), final permutation IP^-1. */
    static int[] feistel(int[] block64, int[][] keys, RoundFunction f) {
        int[][] states = trace(block64, keys, f);
        int[] last = states[keys.length];
        int[] swapped = join(Arrays.copyOfRange(last, HALF_BITS, BLOCK_BITS), Arrays.copyOfRange(last, 0, HALF_BITS));
        return BitUtils.permute(swapped, HbeaTables.fp());
    }

    /** Returns the round keys in reverse order: RK8, RK7, ..., RK1. */
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

/* Output: no main method. See EncryptionDemo.java and DecryptionDemo.java for
   runs, and HbeaCipherTest for its unit tests:
PASS  Encrypting a message > The ciphertext has 64 hex digits
PASS  Encrypting a message > The ciphertext is different from the plaintext
PASS  Encrypting a message > A key generator that returns the wrong shape is rejected
PASS  Encrypting a message > A different key gives a different ciphertext
PASS  Encrypting a message > No public method of HbeaCipher returns key material (encapsulation, Section 5.3)
PASS  Encrypting a message > The same message and key always give the same ciphertext
PASS  Encrypting a message > HbeaCipher can be used through the Cipher interface
PASS  Encrypting a message > An invalid message is rejected before encrypting
PASS  Encrypting a message > A missing key generator or round function is rejected
PASS  Whole block: IP -> rounds -> swap -> IP^-1 > With the 16 DES subkeys the structure gives the real DES ciphertext 85E813540F0AB405
PASS  Whole block: IP -> rounds -> swap -> IP^-1 > The first letter of my name, L, encrypts to the same block as the steps done one by one
PASS  Each encryption round > In every round the new left half is the previous right half
PASS  Each encryption round > Each round matches Olivia's RoundDemo (block "olivia  ") > round 0
PASS  Each encryption round > Each round matches Olivia's RoundDemo (block "olivia  ") > round 1
PASS  Each encryption round > Each round matches Olivia's RoundDemo (block "olivia  ") > round 2
PASS  Each encryption round > Each round matches Olivia's RoundDemo (block "olivia  ") > round 3
PASS  Each encryption round > Each round matches Olivia's RoundDemo (block "olivia  ") > round 4
PASS  Each encryption round > Each round matches Olivia's RoundDemo (block "olivia  ") > round 5
PASS  Each encryption round > Each round matches Olivia's RoundDemo (block "olivia  ") > round 6
PASS  Each encryption round > Each round matches Olivia's RoundDemo (block "olivia  ") > round 7
PASS  Each encryption round > Each round matches Olivia's RoundDemo (block "olivia  ") > round 8
PASS  Each encryption round > A block that is not 64 bits is rejected
PASS  Each encryption round > Round 1 of "Meet me " gives L1 = 00FE2100 and R1 = 0488C614 (spec)
PASS  Each encryption round > After IP, block "Meet me " splits into L0 = 6F086F67 and R0 = 00FE2100 (spec)
PASS  Round keys: RK(i) = E(KS(i)) > There are 8 round keys of 48 bits
PASS  Round keys: RK(i) = E(KS(i)) > Every round key is the expansion of the matching key segment
PASS  Round keys: RK(i) = E(KS(i)) > Asking for a round outside 1..8 is rejected
PASS  Round keys: RK(i) = E(KS(i)) > RK1 for student@student.ie.edu is 358053CF7D00 (spec)
28 tests successful, 0 failed
*/
