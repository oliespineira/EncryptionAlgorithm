package hbea;

import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Scanner;

/**
 * Main: console demo of the whole project (Tasks 5 and 6, Appendix C screenshots).
 *
 * <p>It reads an e-mail and a message, then runs {@link SecureMessenger} first
 * with HbeaCipher and then with XorCipher. Main and SecureMessenger refer to the
 * ciphers only through the {@link Cipher} type, so swapping algorithms means
 * changing only the {@code new ...} expression in {@link #createCipher(String)}.</p>
 *
 * <p>Error handling (Chapter 14): invalid input is caught and the user is asked
 * again instead of the program crashing; the Scanner is closed automatically
 * (try-with-resources); missing input and file errors are handled; a
 * {@code finally} block reports that the file step is over in every case.</p>
 */
public class Main {

    private static final String ARCHIVE_FILE = "messages.txt";

    public static void main(String[] args) {
        try (Scanner in = new Scanner(System.in)) {
            String email = readEmail(in, "Your e-mail (key seed): ");

            Cipher hbea = createCipher(email);
            Cipher xor = new XorCipher(email);    // second algorithm, for the polymorphism demo

            String message = readMessage(in, hbea);
            String otherEmail = readEmail(in, "A different e-mail (for the wrong-key test): ");
            System.out.println();

            // Task 6, polymorphism: the SAME method runs with two different ciphers.
            Cipher[] ciphers = { hbea, xor };
            for (Cipher cipher : ciphers) {
                runDemo(new SecureMessenger(cipher), message);
            }

            wrongKeyTest(hbea, createCipher(otherEmail), message, otherEmail);
            fileDemo(hbea, message);

        } catch (NoSuchElementException e) {
            // Thrown by Scanner.nextLine() when the input ends (e.g. Ctrl+D / Ctrl+Z).
            System.out.println();
            System.out.println("No more input: the program stops without encrypting anything.");
        } catch (InvalidMessageException e) {
            // Should not happen: the message was already validated by readMessage.
            System.out.println("Invalid message: " + e.getMessage());
        }
    }

    /**
     * The ONE line that chooses the main algorithm (Section 5.3). Replacing
     * {@code new HbeaCipher(email)} with {@code new XorCipher(email)} switches the
     * whole program, wrong-key test and file demo included, to the other cipher.
     */
    private static Cipher createCipher(String email) {
        return new HbeaCipher(email);
    }

    /** Asks until the user types something that looks like an e-mail (not blank, has '@'). */
    private static String readEmail(Scanner in, String prompt) {
        while (true) {
            System.out.print(prompt);
            String email = in.nextLine();
            if (!email.isBlank() && email.contains("@")) {
                return email;
            }
            System.out.println("  Invalid e-mail: it must not be empty and must contain '@'. Please try again.");
        }
    }

    /** Asks until the message is accepted by the cipher (InvalidMessageException is caught). */
    private static String readMessage(Scanner in, Cipher cipher) {
        while (true) {
            System.out.print("Message (max 32 printable ASCII characters): ");
            String message = in.nextLine();
            try {
                cipher.encrypt(message);          // validation happens inside encrypt
                return message;
            } catch (InvalidMessageException e) {
                System.out.println("  Invalid message: " + e.getMessage());
                System.out.println("  Please try again.");
            }
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

    /** Task 5: decrypting with a different e-mail must NOT give the message back. */
    private static void wrongKeyTest(Cipher sender, Cipher wrongReceiver, String message, String otherEmail)
            throws InvalidMessageException {
        System.out.println("=== Wrong-key test (" + sender.getName() + ") ===");
        String ciphertext = new SecureMessenger(sender).send(message);
        String attempt = new SecureMessenger(wrongReceiver).receive(ciphertext);
        System.out.println("Decrypted with " + otherEmail.trim() + ": " + printable(attempt));
        System.out.println("Original recovered? " + (attempt.equals(message) ? "YES (unexpected!)" : "NO, as expected"));
        System.out.println();
    }

    /** Sender writes only the ciphertext to a file; receiver reads it back and decrypts. */
    private static void fileDemo(Cipher cipher, String message) throws InvalidMessageException {
        System.out.println("=== Saving to a file and reading it back (" + cipher.getName() + ") ===");
        MessageArchive archive = new MessageArchive(ARCHIVE_FILE);
        SecureMessenger messenger = new SecureMessenger(cipher);
        try {
            List<String> outgoing = new ArrayList<>();
            outgoing.add(messenger.send(message));
            archive.save(cipher.getName(), outgoing);
            System.out.println("Saved ciphertext to " + archive.getPath());

            for (String hex : archive.load(cipher.getName())) {
                System.out.println("Read from file and decrypted: " + messenger.receive(hex));
            }
            new MessageArchive("does-not-exist.txt").load(cipher.getName());
        } catch (FileNotFoundException e) {
            System.out.println("File problem handled: " + e.getMessage());
        } finally {
            System.out.println("File step finished.");
        }
    }

    /** Shows wrong-key garbage safely: non-printable bytes are replaced by '.'. */
    private static String printable(String text) {
        StringBuilder sb = new StringBuilder();
        for (char c : text.toCharArray()) {
            sb.append(c >= 32 && c <= 126 ? c : '.');
        }
        return sb.toString();
    }
}

/* Output:
Your e-mail (key seed): liglesias.ieu2024@student.ie.edu
Message (max 32 printable ASCII characters): café
  Invalid message: Invalid character 'é' (code 233) at position 3: only printable ASCII (32-126) is allowed.
  Please try again.
Message (max 32 printable ASCII characters): Meet me at the library at 5pm!!!
A different e-mail (for the wrong-key test): someone.else@student.ie.edu

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
Decrypted with someone.else@student.ie.edu: ..F.X6.e..F0.....6~.L9.H"b......
Original recovered? NO, as expected

=== Saving to a file and reading it back (HBEA) ===
Saved ciphertext to messages.txt
Read from file and decrypted: Meet me at the library at 5pm!!!
File problem handled: does-not-exist.txt (No such file or directory)
File step finished.
*/
