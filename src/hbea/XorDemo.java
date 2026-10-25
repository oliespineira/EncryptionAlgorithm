package hbea;

/**
 * Task 3 demo: callers of BitUtils.xor handle invalid input gracefully
 * with try/catch instead of letting the program crash.
 */
public class XorDemo {

    public static void main(String[] args) {
        tryXor("Equal lengths", BitUtils.fromHex("F0"), BitUtils.fromHex("3C"));
        tryXor("Different lengths", new int[32], new int[48]);
        tryXor("Null input", null, new int[32]);
        System.out.println("Program finished normally.");
    }

    /** Calls xor and catches the exception so the program keeps running. */
    private static void tryXor(String label, int[] a, int[] b) {
        try {
            int[] result = BitUtils.xor(a, b);
            System.out.println(label + " -> OK: " + BitUtils.toHex(result));
        } catch (IllegalArgumentException e) {
            System.out.println(label + " -> handled error: " + e.getMessage());
        }
    }
}

/* Output:
Equal lengths -> OK: CC
Different lengths -> handled error: xor: arrays must have the same length (32 vs 48).
Null input -> handled error: xor: arrays must not be null.
Program finished normally.
*/