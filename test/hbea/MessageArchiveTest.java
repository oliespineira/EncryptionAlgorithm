package hbea;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** BDD scenarios for MessageArchive: text-file I/O with exception handling (Chapter 14). */
@DisplayName("Feature: saving encrypted messages to a file")
class MessageArchiveTest {

    @TempDir
    Path tempDir;   // JUnit creates and deletes a temporary folder for each test

    private String file(String name) {
        return tempDir.resolve(name).toString();
    }

    @Test
    @DisplayName("Given a ciphertext saved to a file, When the receiver loads and decrypts it, Then the message comes back")
    void saveThenLoadRoundTrip() throws Exception {
        Cipher cipher = new HbeaCipher(StudentConfig.EMAIL);
        MessageArchive archive = new MessageArchive(file("messages.txt"));
        String hex = cipher.encrypt("See you at 5");

        archive.save(cipher.getName(), List.of(hex));
        List<String> loaded = archive.load(cipher.getName());

        assertEquals(List.of(hex), loaded);
        assertEquals("See you at 5", cipher.decrypt(loaded.get(0)));
    }

    @Test
    @DisplayName("Given a file, When it is read, Then the plaintext is not in it")
    void plaintextIsNeverWritten() throws Exception {
        Cipher cipher = new HbeaCipher(StudentConfig.EMAIL);
        MessageArchive archive = new MessageArchive(file("secret.txt"));
        archive.save(cipher.getName(), List.of(cipher.encrypt("top secret")));

        String content = java.nio.file.Files.readString(tempDir.resolve("secret.txt"));
        assertFalse(content.contains("top secret"));
    }

    @Test
    @DisplayName("Given a file that does not exist, When it is loaded, Then FileNotFoundException is thrown")
    void missingFile() {
        MessageArchive archive = new MessageArchive(file("nope.txt"));
        assertThrows(FileNotFoundException.class, () -> archive.load("HBEA"));
    }

    @Test
    @DisplayName("Given a file with a corrupted line, When it is loaded, Then that line is skipped and the rest is kept")
    void corruptedLineSkipped() throws Exception {
        String hex = new HbeaCipher(StudentConfig.EMAIL).encrypt("ok");
        File f = tempDir.resolve("mixed.txt").toFile();
        try (PrintWriter out = new PrintWriter(f)) {
            out.println("HBEA THIS-IS-NOT-HEX");
            out.println("HBEA " + hex);
            out.println("XOR " + hex);
        }
        assertEquals(List.of(hex), new MessageArchive(f.getPath()).load("HBEA"));
    }

    @Test
    @DisplayName("Given an invalid ciphertext, When it is saved, Then IllegalArgumentException is thrown")
    void invalidCiphertextNotSaved() {
        MessageArchive archive = new MessageArchive(file("bad.txt"));
        assertThrows(IllegalArgumentException.class, () -> archive.save("HBEA", List.of("ABC")));
    }

    @Test
    @DisplayName("Given a blank file name, When the archive is created, Then IllegalArgumentException is thrown")
    void blankFileName() {
        assertThrows(IllegalArgumentException.class, () -> new MessageArchive(" "));
        assertThrows(IllegalArgumentException.class, () -> new MessageArchive(null));
    }
}

/* Test results (JUnit 5):
PASS  Given an invalid ciphertext, When it is saved, Then IllegalArgumentException is thrown
PASS  Given a blank file name, When the archive is created, Then IllegalArgumentException is thrown
PASS  Given a ciphertext saved to a file, When the receiver loads and decrypts it, Then the message comes back
PASS  Given a file with a corrupted line, When it is loaded, Then that line is skipped and the rest is kept
PASS  Given a file that does not exist, When it is loaded, Then FileNotFoundException is thrown
PASS  Given a file, When it is read, Then the plaintext is not in it
6 tests successful, 0 failed
*/
