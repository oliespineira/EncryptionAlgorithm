package hbea;

/**
 * DecryptionDemo: Task 5 demo. Decrypts with the round keys in reverse order
 * (RK8 first), shows every round of the decryption, and shows that a different
 * e-mail does not recover the message.
 */
public class DecryptionDemo {

    public static void main(String[] args) {
        HbeaCipher sender = new HbeaCipher(StudentConfig.EMAIL);
        HbeaCipher receiver = new HbeaCipher(StudentConfig.EMAIL);   // separate object, same key

        System.out.println("=== HBEA decryption demo ===");
        System.out.println("Key (email): " + StudentConfig.EMAIL);
        System.out.println();

        try {
            String message = "Meet me at the library at 5pm!!!";
            String ciphertext = sender.encrypt(message);
            System.out.println("--- Full 32-character message ---");
            System.out.println("Plaintext:  " + message);
            System.out.println("Ciphertext: " + ciphertext);
            System.out.println("Decrypted:  " + receiver.decrypt(ciphertext));
            System.out.println();

            String name = StudentConfig.FIRST_NAME;
            String nameCipher = sender.encrypt(name);
            System.out.println("--- Block starting with my name: \"" + name + "\" ---");
            System.out.println("Ciphertext: " + nameCipher);
            int[] encryptedBlock = BitUtils.fromHex(nameCipher.substring(0, 16));
            int[][] states = receiver.traceDecryption(encryptedBlock);
            for (int round = 0; round < states.length; round++) {
                String hex = BitUtils.toHex(states[round]);
                String label = (round == 0) ? "After IP" : "Round " + round + " (RK" + (HbeaCipher.ROUNDS + 1 - round) + ")";
                System.out.println(label + ": L = " + hex.substring(0, 8) + "  R = " + hex.substring(8));
            }
            String decryptedName = receiver.decrypt(nameCipher);
            System.out.println("Decrypted: \"" + decryptedName + "\" (" + decryptedName.length()
                    + " character(s), padding removed)");
            System.out.println();

            System.out.println("--- Wrong key ---");
            HbeaCipher wrong = new HbeaCipher(StudentConfig.OTHER_EMAIL);
            String garbage = wrong.decrypt(ciphertext);
            System.out.println("Decrypted with " + StudentConfig.OTHER_EMAIL + ": "
                    + (garbage.equals(message) ? "original recovered" : "original NOT recovered"));
            System.out.println();

            System.out.println("Round trip check: " + (sender.verifyRoundTrip(message) ? "OK" : "FAILED"));
        } catch (InvalidMessageException e) {
            System.out.println("Could not encrypt: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.out.println("Could not decrypt: " + e.getMessage());
        }
    }
}

/* Output:
=== HBEA decryption demo ===
Key (email): liglesias.ieu2024@student.ie.edu

--- Full 32-character message ---
Plaintext:  Meet me at the library at 5pm!!!
Ciphertext: 9F61A7606FAF6716DA9C2E64EEEEC4D0C43AC1100095F67B4081A8FE511AE46D
Decrypted:  Meet me at the library at 5pm!!!

--- Block starting with my name: "L" ---
Ciphertext: 28C405D86E90D2A6583F460CA8248E37583F460CA8248E37583F460CA8248E37
After IP: L = 5A689604  R = EA9119D0
Round 1 (RK8): L = EA9119D0  R = 8074190E
Round 2 (RK7): L = 8074190E  R = 5CAC0E14
Round 3 (RK6): L = 5CAC0E14  R = 6D6E4F86
Round 4 (RK5): L = 6D6E4F86  R = E5585249
Round 5 (RK4): L = E5585249  R = 8CAAE8E3
Round 6 (RK3): L = 8CAAE8E3  R = 2BA74364
Round 7 (RK2): L = 2BA74364  R = 00000100
Round 8 (RK1): L = 00000100  R = 01000100
Decrypted: "L" (1 character(s), padding removed)

--- Wrong key ---
Decrypted with someone.else@student.ie.edu: original NOT recovered

Round trip check: OK
*/
