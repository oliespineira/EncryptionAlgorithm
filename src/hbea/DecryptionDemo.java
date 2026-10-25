package hbea;

public class DecryptionDemo {
    private static final String OFFICIAL_EMAIL = "liglesias.ieu2024@student.ie.edu";
    private static final String OTHER_EMAIL = "oespineira.ieu2024@student.ie.edu";

    public static void main(String[] args) throws InvalidMessageException {
        HbeaCipher sender = new HbeaCipher(OFFICIAL_EMAIL);
        HbeaCipher receiver = new HbeaCipher(OFFICIAL_EMAIL);

        System.out.println("=== HBEA decryption demo ===");
        System.out.println("Key (email): " + OFFICIAL_EMAIL);
        System.out.println();

        String message = "Meet me at the library at 5pm!!!";
        String ciphertext = sender.encrypt(message);
        System.out.println("--- Full 32-character message ---");
        System.out.println("Plaintext:  " + message);
        System.out.println("Ciphertext: " + ciphertext);
        System.out.println("Decrypted:  " + receiver.decrypt(ciphertext));
        System.out.println();

        String letter = "L";
        String letterCipher = sender.encrypt(letter);
        System.out.println("--- First letter of my name: \"" + letter + "\" ---");
        System.out.println("Ciphertext: " + letterCipher);
        int[] encryptedBlock = BitUtils.fromHex(letterCipher.substring(0, 16));
        int[][] states = receiver.traceDecryption(encryptedBlock);
        for (int round = 0; round < states.length; round++) {
            String hex = BitUtils.toHex(states[round]);
            String label = (round == 0) ? "After IP" : "Round " + round + " (RK" + (HbeaCipher.ROUNDS + 1 - round) + ")";
            System.out.println(label + ": L = " + hex.substring(0, 8) + "  R = " + hex.substring(8));
        }
        String decryptedLetter = receiver.decrypt(letterCipher);
        System.out.println("Decrypted: \"" + decryptedLetter + "\" (" + decryptedLetter.length() + " character, padding removed)");
        System.out.println();

        System.out.println("--- Wrong key ---");
        HbeaCipher wrong = new HbeaCipher(OTHER_EMAIL);
        String garbage = wrong.decrypt(ciphertext);
        System.out.println("Decrypted with " + OTHER_EMAIL + ": " + (garbage.equals(message) ? "original recovered" : "original NOT recovered"));
        System.out.println();

        System.out.println("Round trip check: " + (sender.verifyRoundTrip(message) ? "OK" : "FAILED"));
    }
}