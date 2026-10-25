package hbea;

import java.nio.charset.StandardCharsets;

public class EncryptionDemo {
    private static final String OFFICIAL_EMAIL = "liglesias.ieu2024@student.ie.edu";

    public static void main(String[] args) throws InvalidMessageException {
        HbeaCipher cipher = new HbeaCipher(OFFICIAL_EMAIL);

        System.out.println("=== HBEA encryption demo ===");
        System.out.println("Key (email): " + OFFICIAL_EMAIL);
        System.out.println();

        String letter = "L";
        System.out.println("--- First letter of my name: \"" + letter + "\" ---");
        int[] firstBlock = AbstractBlockCipher.toBlocks(AbstractBlockCipher.pad(letter))[0];
        System.out.println("Block 1 (\"L\" + padding) = " + BitUtils.toHex(firstBlock));
        int[][] states = cipher.trace(firstBlock);
        for (int round = 0; round < states.length; round++) {
            String hex = BitUtils.toHex(states[round]);
            String label = (round == 0) ? "After IP" : "Round " + round;
            System.out.println(label + ": L = " + hex.substring(0, 8) + "  R = " + hex.substring(8));
        }
        String letterCipher = cipher.encrypt(letter);
        System.out.println("Encrypted block 1 = " + letterCipher.substring(0, 16));
        System.out.println("Ciphertext of \"L\": " + letterCipher);
        System.out.println();

        String message = "Meet me at the library at 5pm!!!";
        System.out.println("--- Full 32-character message ---");
        System.out.println("Plaintext:  " + message);
        System.out.println("Plain hex:  " + BitUtils.toHex(BitUtils.bytesToBits(message.getBytes(StandardCharsets.US_ASCII))));
        System.out.println("Ciphertext: " + cipher.encrypt(message));
    }
}
