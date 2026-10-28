package hbea;

/**
 * RoundFunction: the function F used inside every Feistel round.
 *
 * <p>Because HbeaCipher receives a RoundFunction in its constructor (composition
 * through an interface), a different F could be plugged in without changing
 * HbeaCipher. F does not need to be reversible: the Feistel structure is what
 * makes decryption possible.</p>
 */
public interface RoundFunction {

    /**
     * @param right32    the 32-bit right half of the block
     * @param roundKey48 the 48-bit round key
     * @return 32 bits
     */
    int[] apply(int[] right32, int[] roundKey48); // returns 32 bits
}

/* Output: interface, it has no main method. See DesRoundFunctionTest (unit tests
   against Section 7) and RoundDemo.java for its output. */
