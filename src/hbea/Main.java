package hbea;

import java.util.Scanner;

/**
 * Main: console demo of the whole project (Tasks 5 and 6).
 *
 * Reads an e-mail and a message, then runs SecureMessenger first with
 * HbeaCipher and then with XorCipher. Main and SecureMessenger refer to the
 * ciphers only through the Cipher type, so swapping algorithms means changing
 * only the "new ..." expression.
 */
public class Main {

    public static void main(String[] args) {
        Scanner in = new Scanner(System.in);

        System.out.print("Your e-mail (key seed): ");
        String email = in.nextLine();
        System.out.print("Message (max 32 printable ASCII characters): ");
        String message = in.nextLine();
        System.out.print("A different e-mail (for the wrong-key test): ");
        String otherEmail = in.nextLine();
        System.out.println();

        try {
            // The only lines that name concrete classes: change these to swap ciphers.
            Cipher hbea = new HbeaCipher(email);
            Cipher xor = new XorCipher(email);

            // Polymorphism: the SAME method runs with two different ciphers.
            runDemo(new SecureMessenger(hbea), message);
            runDemo(new SecureMessenger(xor), message);

            // Wrong-key test with HBEA
            System.out.println("=== Wrong-key test (HBEA) ===");
            String ciphertext = new SecureMessenger(hbea).send(message);
            SecureMessenger wrongReceiver = new SecureMessenger(new HbeaCipher(otherEmail));
            String attempt = wrongReceiver.receive(ciphertext);
            System.out.println("Decrypted with " + otherEmail.trim() + ": "
                    + (attempt.equals(message) ? "original recovered (unexpected!)" : "original NOT recovered"));
        } catch (InvalidMessageException e) {
            System.out.println("Invalid message: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid input: " + e.getMessage());
        }
    }

    /** Works with ANY cipher, because SecureMessenger only knows the Cipher interface. */
    private static void runDemo(SecureMessenger messenger, String message) throws InvalidMessageException {
        System.out.println("=== Cipher: " + messenger.getCipherName() + " ===");
        String ciphertext = messenger.send(message);
        System.out.println("Plaintext:  " + message);
        System.out.println("Ciphertext: " + ciphertext);
        System.out.println("Decrypted:  " + messenger.receive(ciphertext));
        System.out.println("Round trip: " + (messenger.selfCheck(message) ? "OK" : "FAILED"));
        System.out.println();
    }
}

/* Output (input: liglesias.ieu2024@student.ie.edu / Meet me at the library at 5pm!!! / oespineira.ieu2024@student.ie.edu):
Your e-mail (key seed): Message (max 32 printable ASCII characters): A different e-mail (for the wrong-key test):
=== Cipher: HBEA ===
Plaintext:  Meet me at the library at 5pm!!!
Ciphertext: 9F61A7606FAF6716DA9C2E64EEEEC4D0C43AC1100095F67B4081A8FE511AE46D
Decrypted:  Meet me at the library at 5pm!!!
Round trip: OK

=== Cipher: XOR ===
Plaintext:  Meet me at the library at 5pm!!!
Ciphertext: 9A72D019F7EC0C25B6639519BFE44969BE75C70CA5F84964A337801DBAA04824
Decrypted:  Meet me at the library at 5pm!!!
Round trip: OK

=== Wrong-key test (HBEA) ===
Decrypted with oespineira.ieu2024@student.ie.edu: original NOT recovered
*/
