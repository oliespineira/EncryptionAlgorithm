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

/* Output: no main method; it is exercised by the tests and demos.
PASS  Given SecureMessenger, When I plug in either cipher, Then send/receive works without changing it
PASS  Given the spec key, When I XOR-encrypt 8 NUL bytes, Then I get KS1 + KS2 (the key itself)
PASS  Given the overloaded encrypt(int[]), When the array is not 256 bits, Then IllegalArgumentException is thrown
PASS  Given a null cipher or key generator, When I build the object, Then IllegalArgumentException is thrown
PASS  Given a ciphertext, When I decrypt with a different e-mail, Then the original is NOT recovered
PASS  Given the same message, When encrypted with HBEA and with XOR, Then the ciphertexts differ
PASS  Given my e-mail, When I encrypt with XOR and decrypt, Then I get the original back
PASS  Given an invalid message, When I send it, Then InvalidMessageException is thrown
8 tests successful, 0 failed
*/
