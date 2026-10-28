package hbea;

import java.nio.charset.StandardCharsets;

/**
 * EncryptionDemo: Task 4 demo. Encrypts a block that starts with the first letter
 * of my name and prints L and R after IP and after each of the 8 rounds, then
 * encrypts a full 32-character message.
 */
public class EncryptionDemo {

    public static void main(String[] args) {
        HbeaCipher cipher = new HbeaCipher(StudentConfig.EMAIL);

        System.out.println("=== HBEA encryption demo ===");
        System.out.println("Key (email): " + StudentConfig.EMAIL);
        System.out.println();

        try {
            String name = StudentConfig.FIRST_NAME;
            System.out.println("--- Block starting with my name: \"" + name + "\" ---");
            int[] firstBlock = AbstractBlockCipher.toBlocks(AbstractBlockCipher.prepare(name))[0];
            System.out.println("Block 1 (\"" + name + "\" + NUL padding) = " + BitUtils.toHex(firstBlock));
            int[][] states = cipher.trace(firstBlock);
            for (int round = 0; round < states.length; round++) {
                String hex = BitUtils.toHex(states[round]);
                String label = (round == 0) ? "After IP" : "Round " + round;
                System.out.println(label + ": L = " + hex.substring(0, 8) + "  R = " + hex.substring(8));
            }
            String nameCipher = cipher.encrypt(name);
            System.out.println("Encrypted block 1 = " + nameCipher.substring(0, 16));
            System.out.println("Ciphertext of \"" + name + "\": " + nameCipher);
            System.out.println();

            String message = "Meet me at the library at 5pm!!!";
            System.out.println("--- Full 32-character message ---");
            System.out.println("Plaintext:  " + message);
            System.out.println("Plain hex:  " + BitUtils.toHex(BitUtils.bytesToBits(message.getBytes(StandardCharsets.US_ASCII))));
            System.out.println("Ciphertext: " + cipher.encrypt(message));
        } catch (InvalidMessageException e) {
            System.out.println("Could not encrypt: " + e.getMessage());
        }
    }
}

/* Output:
=== HBEA encryption demo ===
Key (email): liglesias.ieu2024@student.ie.edu

--- Block starting with my name: "L" ---
Block 1 ("L" + NUL padding) = 4C00000000000000
After IP: L = 01000100  R = 00000100
Round 1: L = 00000100  R = 2BA74364
Round 2: L = 2BA74364  R = 8CAAE8E3
Round 3: L = 8CAAE8E3  R = E5585249
Round 4: L = E5585249  R = 6D6E4F86
Round 5: L = 6D6E4F86  R = 5CAC0E14
Round 6: L = 5CAC0E14  R = 8074190E
Round 7: L = 8074190E  R = EA9119D0
Round 8: L = EA9119D0  R = 5A689604
Encrypted block 1 = 28C405D86E90D2A6
Ciphertext of "L": 28C405D86E90D2A6583F460CA8248E37583F460CA8248E37583F460CA8248E37

--- Full 32-character message ---
Plaintext:  Meet me at the library at 5pm!!!
Plain hex:  4D656574206D6520617420746865206C6962726172792061742035706D212121
Ciphertext: 9F61A7606FAF6716DA9C2E64EEEEC4D0C43AC1100095F67B4081A8FE511AE46D
*/
