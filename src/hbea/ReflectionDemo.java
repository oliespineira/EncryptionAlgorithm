package hbea;

/**
 * ReflectionDemo: evidence for reflection question 2 of the report.
 *
 * <p>"Hi Anas" has 7 characters, so 25 NUL characters are added. Blocks 2, 3 and 4
 * are then all eight NULs, and because every block is encrypted independently
 * with the same round keys, identical plaintext blocks give identical ciphertext
 * blocks. An attacker learns where the message repeats (or where it ends) without
 * knowing the key. This weakness is known as ECB mode.</p>
 */
public class ReflectionDemo {

    public static void main(String[] args) {
        Cipher cipher = new HbeaCipher(StudentConfig.EMAIL);
        try {
            String message = "Hi Anas";
            String hex = cipher.encrypt(message);
            System.out.println("Message: \"" + message + "\" (" + message.length() + " characters + "
                    + (32 - message.length()) + " NUL padding)");
            for (int b = 0; b < 4; b++) {
                System.out.println("Ciphertext block " + (b + 1) + ": " + hex.substring(b * 16, (b + 1) * 16));
            }
            boolean sameTail = hex.substring(16, 32).equals(hex.substring(32, 48))
                    && hex.substring(32, 48).equals(hex.substring(48, 64));
            System.out.println("Blocks 2, 3 and 4 identical? " + (sameTail ? "YES" : "NO"));
        } catch (InvalidMessageException e) {
            System.out.println("Could not encrypt: " + e.getMessage());
        }
    }
}

/* Output:
Message: "Hi Anas" (7 characters + 25 NUL padding)
Ciphertext block 1: A3FDCC4C18EAED9F
Ciphertext block 2: 583F460CA8248E37
Ciphertext block 3: 583F460CA8248E37
Ciphertext block 4: 583F460CA8248E37
Blocks 2, 3 and 4 identical? YES
*/
