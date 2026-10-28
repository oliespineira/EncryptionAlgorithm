package hbea;

/**
 * XorCipher: a deliberately simple second cipher (Section 5.2).
 *
 * Each 64-bit block is XOR-ed with the first 64 bits of the SHA-256 key
 * (key segments KS1 + KS2). Because x XOR k XOR k = x, encrypting and
 * decrypting are exactly the same operation.
 *
 * It exists to show polymorphism: it fulfils the same Cipher contract as
 * HbeaCipher, so SecureMessenger can use either one without changing.
 * It is NOT secure (every block uses the same key bits).
 */
public class XorCipher extends AbstractBlockCipher {

    /** The first 64 key bits. private final = encapsulated, never exposed. */
    private final int[] key64;

    /** Builds the cipher with the default SHA-256 key generator. */
    public XorCipher(String email) {
        this(email, new Sha256KeyGenerator());
    }

    /** Overloaded constructor: any KeyGenerator can be plugged in (composition through an interface). */
    public XorCipher(String email, KeyGenerator keyGenerator) {
        if (keyGenerator == null) {
            throw new IllegalArgumentException("Key generator must not be null.");
        }
        int[][] segments = keyGenerator.generateKeySegments(email);
        key64 = new int[BLOCK_BITS];
        // KS1 goes into bits 0-31, KS2 into bits 32-63
        System.arraycopy(segments[0], 0, key64, 0, KeyGenerator.SEGMENT_BITS);
        System.arraycopy(segments[1], 0, key64, KeyGenerator.SEGMENT_BITS, KeyGenerator.SEGMENT_BITS);
    }

    @Override
    protected int[] encryptBlock(int[] block64) {
        return BitUtils.xor(block64, key64);
    }

    @Override
    protected int[] decryptBlock(int[] block64) {
        return BitUtils.xor(block64, key64);   // same as encrypting: XOR undoes itself
    }

    @Override
    public String getName() {
        return "XOR";
    }
}