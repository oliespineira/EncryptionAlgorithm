package hbea;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public class KeyGenerationDemo {
    private static final String OFFICIAL_EMAIL = "liglesias.ieu2024@student.ie.edu";

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String email = (args.length > 0) ? args[0] : OFFICIAL_EMAIL;
        demo(email);
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

        String normalised = email.trim().toLowerCase();
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

