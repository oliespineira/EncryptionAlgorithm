package hbea;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * MessageArchive: saves encrypted messages to a text file and reads them back.
 *
 * <p>This simulates "sending" a message: the sender writes only the ciphertext to
 * a file, and the receiver later reads it and decrypts it with the same key. The
 * plaintext is never written to disk.</p>
 *
 * <p>Concepts shown (Chapter 14, Exception Handling and Text I/O): writing with
 * {@link PrintWriter}, reading with {@link Scanner} and {@link File},
 * {@link FileNotFoundException} (a checked exception declared with
 * {@code throws}), and a {@code finally} block that always closes the file.</p>
 *
 * <p>File format: one line per message, {@code <cipher name> <64 hex digits>}.</p>
 */
public class MessageArchive {

    private final File file;

    /**
     * @param fileName the text file to use
     * @throws IllegalArgumentException if the name is null or blank
     */
    public MessageArchive(String fileName) {
        if (fileName == null || fileName.isBlank()) {
            throw new IllegalArgumentException("File name must not be empty.");
        }
        this.file = new File(fileName);
    }

    /** @return the path of the archive file */
    public String getPath() {
        return file.getPath();
    }

    /**
     * Writes the ciphertexts to the file (overwriting it).
     *
     * @param cipherName  the algorithm used, so the receiver knows which one to use
     * @param ciphertexts the 64-hex-digit messages
     * @throws FileNotFoundException if the file cannot be created
     */
    public void save(String cipherName, List<String> ciphertexts) throws FileNotFoundException {
        PrintWriter output = null;
        try {
            output = new PrintWriter(file);
            for (String hex : ciphertexts) {
                AbstractBlockCipher.validateCipherHex(hex);     // never write a corrupted line
                output.println(cipherName + " " + hex);
            }
        } finally {
            // Runs whether or not an exception happened: the file is always closed.
            if (output != null) {
                output.close();
            }
        }
    }

    /**
     * Reads back the ciphertexts written for one algorithm. Lines that are badly
     * formed are skipped with a warning instead of stopping the whole read.
     *
     * @param cipherName only lines for this algorithm are returned
     * @return the ciphertexts, in file order
     * @throws FileNotFoundException if the file does not exist
     */
    public List<String> load(String cipherName) throws FileNotFoundException {
        List<String> result = new ArrayList<>();
        Scanner input = null;
        try {
            input = new Scanner(file);
            int lineNumber = 0;
            while (input.hasNextLine()) {
                lineNumber++;
                String line = input.nextLine().trim();
                String[] parts = line.split(" ");
                try {
                    if (parts.length != 2) {
                        throw new IllegalArgumentException("expected '<name> <hex>'");
                    }
                    AbstractBlockCipher.validateCipherHex(parts[1]);
                    if (parts[0].equals(cipherName)) {
                        result.add(parts[1]);
                    }
                } catch (IllegalArgumentException e) {
                    System.out.println("  Skipping line " + lineNumber + " of " + file.getName()
                            + ": " + e.getMessage());
                }
            }
        } finally {
            if (input != null) {
                input.close();
            }
        }
        return result;
    }
}

/* Output: no main method; used by Main (see the "Saving to a file" part of the
   output at the end of Main.java) and tested in MessageArchiveTest:
PASS  Given an invalid ciphertext, When it is saved, Then IllegalArgumentException is thrown
PASS  Given a blank file name, When the archive is created, Then IllegalArgumentException is thrown
PASS  Given a ciphertext saved to a file, When the receiver loads and decrypts it, Then the message comes back
PASS  Given a file with a corrupted line, When it is loaded, Then that line is skipped and the rest is kept
PASS  Given a file that does not exist, When it is loaded, Then FileNotFoundException is thrown
PASS  Given a file, When it is read, Then the plaintext is not in it
6 tests successful, 0 failed
*/
