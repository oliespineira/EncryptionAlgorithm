package hbea;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;

/**
 * KeyGenerationDemo: Task 2 demo. Prints KS1 ... KS8 for an e-mail and checks
 * them against an independent SHA-256 computation.
 */
public class KeyGenerationDemo {

    public static void main(String[] args) {
        String email = (args.length > 0) ? args[0] : StudentConfig.EMAIL;
        try {
            demo(email);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("SHA-256 is not available on this Java installation: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid seed: " + e.getMessage());
        }
    }

    public static boolean demo(String email) throws NoSuchAlgorithmException {
        KeyGenerator generator = new Sha256KeyGenerator();
        int[][] segments = generator.generateKeySegments(email);

        System.out.println("=== HBEA key generation demo ===");
        System.out.println("Seed (email): " + email);
        System.out.println("Segments: " + segments.length + " x " + segments[0].length + " bits");
        System.out.println();

        StringBuilder joined = new StringBuilder();
        for (int i = 0; i < segments.length; i++) {
            String hex = BitUtils.toHex(segments[i]);
            joined.append(hex);
            System.out.printf("KS%d = %s = %s%n", i + 1, hex, bitsToString(segments[i]));
        }

        String normalised = email.trim().toLowerCase(Locale.ROOT);
        byte[] reference = MessageDigest.getInstance("SHA-256")
                .digest(normalised.getBytes(StandardCharsets.UTF_8));
        String expected = HexFormat.of().withUpperCase().formatHex(reference);
        boolean ok = expected.equals(joined.toString());

        System.out.println();
        System.out.println("Generated key (KS1..KS8): " + joined);
        System.out.println("SHA-256(email) reference: " + expected);
        System.out.println(ok ? "VERIFIED: the key segments match SHA-256 of the email."
                : "ERROR: the key segments do NOT match SHA-256 of the email.");
        return ok;
    }

    private static String bitsToString(int[] bits) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bits.length; i++) {
            if (i > 0 && i % 8 == 0) {
                sb.append(' ');
            }
            sb.append(bits[i]);
        }
        return sb.toString();
    }
}

/* Output:
=== HBEA key generation demo ===
Seed (email): liglesias.ieu2024@student.ie.edu
Segments: 8 x 32 bits

KS1 = D717B56D = 11010111 00010111 10110101 01101101
KS2 = D7816905 = 11010111 10000001 01101001 00000101
KS3 = B8CACEE8 = 10111000 11001010 11001110 11101000
KS4 = E08D289B = 11100000 10001101 00101000 10011011
KS5 = 90813648 = 10010000 10000001 00110110 01001000
KS6 = 19A73EEE = 00011001 10100111 00111110 11101110
KS7 = C2152276 = 11000010 00010101 00100010 01110110
KS8 = 180819EA = 00011000 00001000 00011001 11101010

Generated key (KS1..KS8): D717B56DD7816905B8CACEE8E08D289B9081364819A73EEEC2152276180819EA
SHA-256(email) reference: D717B56DD7816905B8CACEE8E08D289B9081364819A73EEEC2152276180819EA
VERIFIED: the key segments match SHA-256 of the email.
*/
