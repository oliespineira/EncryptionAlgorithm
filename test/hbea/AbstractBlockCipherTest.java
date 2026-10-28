package hbea;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Data integrity (AbstractBlockCipher)")
/**
 * Task 1 (TDD): validation, padding and splitting, tested through a tiny
 * IdentityCipher subclass so that only AbstractBlockCipher's logic is checked.
 */
class AbstractBlockCipherTest {
    private static final String FULL_MESSAGE = "Meet me at the library at 5pm!!!";

    static class IdentityCipher extends AbstractBlockCipher {
        @Override
        protected int[] encryptBlock(int[] block64) {
            return block64.clone();
        }

        @Override
        protected int[] decryptBlock(int[] block64) {
            return block64.clone();
        }

        @Override
        public String getName() {
            return "Identity (test only)";
        }
    }

    private final AbstractBlockCipher cipher = new IdentityCipher();

    @Nested
    @DisplayName("Validation of the input message")
    class Validation {
        @Test
        @DisplayName("A null message is rejected")
        void nullIsRejected() {
            InvalidMessageException e = assertThrows(InvalidMessageException.class,
                    () -> AbstractBlockCipher.validate(null));
            assertTrue(e.getMessage().contains("null"));
        }

        @Test
        @DisplayName("An empty message is rejected")
        void emptyIsRejected() {
            InvalidMessageException e = assertThrows(InvalidMessageException.class,
                    () -> AbstractBlockCipher.validate(""));
            assertTrue(e.getMessage().contains("empty"));
        }

        @Test
        @DisplayName("A message of 33 characters (one too many) is rejected")
        void thirtyThreeIsRejected() {
            assertThrows(InvalidMessageException.class,
                    () -> AbstractBlockCipher.validate("X".repeat(33)));
        }

        @Test
        @DisplayName("A message longer than 32 characters is rejected")
        void tooLongIsRejected() {
            String tooLong = FULL_MESSAGE + "X";
            InvalidMessageException e = assertThrows(InvalidMessageException.class,
                    () -> AbstractBlockCipher.validate(tooLong));
            assertTrue(e.getMessage().contains("at most"));
        }

        @ParameterizedTest(name = "\"{0}\"")
        @ValueSource(strings = {"caf\u00e9", "a\u00f1o", "tab\there", "new\nline", "smile \u263A", "nul\u0000inside", "del\u007F"})
        @DisplayName("A message with a non-printable or non-ASCII character is rejected")
        void invalidCharactersAreRejected(String message) {
            InvalidMessageException e = assertThrows(InvalidMessageException.class,
                    () -> AbstractBlockCipher.validate(message));
            assertTrue(e.getMessage().contains("Invalid character"));
        }

        @Test
        @DisplayName("A message of exactly 32 printable characters is accepted")
        void fullLengthIsAccepted() {
            assertEquals(32, FULL_MESSAGE.length());
            assertDoesNotThrow(() -> AbstractBlockCipher.validate(FULL_MESSAGE));
        }

        @Test
        @DisplayName("The boundary characters space (32) and ~ (126) are accepted")
        void boundaryCharactersAreAccepted() {
            assertDoesNotThrow(() -> AbstractBlockCipher.validate(" ~"));
        }
    }

    @Nested
    @DisplayName("Short messages are valid and get padded")
    class ShortMessages {
        @Test
        @DisplayName("A message shorter than 32 characters is valid (no exception)")
        void shortMessageIsValid() {
            assertDoesNotThrow(() -> AbstractBlockCipher.validate("Hello"));
        }

        @Test
        @DisplayName("prepare() pads a short message to 32 characters with NUL")
        void prepareRecoversByPadding() throws Exception {
            String prepared = AbstractBlockCipher.prepare("Hello");
            assertEquals(32, prepared.length());
            assertTrue(prepared.startsWith("Hello"));
            for (int i = 5; i < 32; i++) {
                assertEquals(AbstractBlockCipher.PAD_CHAR, prepared.charAt(i));
            }
        }

        @Test
        @DisplayName("prepare() leaves a 32-character message unchanged (no padding)")
        void prepareKeepsFullMessage() throws Exception {
            assertEquals(FULL_MESSAGE, AbstractBlockCipher.prepare(FULL_MESSAGE));
        }

        @Test
        @DisplayName("prepare() does not pad an invalid message: the error reaches the caller")
        void prepareDoesNotHideInvalidMessages() {
            assertThrows(InvalidMessageException.class, () -> AbstractBlockCipher.prepare(""));
            assertThrows(InvalidMessageException.class, () -> AbstractBlockCipher.prepare("caf\u00e9"));
        }

        @Test
        @DisplayName("A 1-character message is accepted and padded with 31 NULs")
        void oneCharacterMessage() throws Exception {
            String prepared = AbstractBlockCipher.prepare("L");
            assertEquals(32, prepared.length());
            assertEquals(31, prepared.chars().filter(c -> c == AbstractBlockCipher.PAD_CHAR).count());
        }
    }

    @Nested
    @DisplayName("Padding and unpadding")
    class Padding {
        @Test
        @DisplayName("unpad(pad(x)) gives back x")
        void unpadReversesPad() {
            assertEquals("Hi", AbstractBlockCipher.unpad(AbstractBlockCipher.pad("Hi")));
        }

        @Test
        @DisplayName("unpad keeps spaces the user typed (only the padding character is removed)")
        void unpadKeepsUserSpaces() {
            assertEquals("Hi  ", AbstractBlockCipher.unpad(AbstractBlockCipher.pad("Hi  ")));
        }

        @Test
        @DisplayName("pad does not change a message that already has 32 characters")
        void padFullMessageUnchanged() {
            assertEquals(FULL_MESSAGE, AbstractBlockCipher.pad(FULL_MESSAGE));
        }
    }

    @Nested
    @DisplayName("Segmentation into 4 blocks of 64 bits")
    class Segmentation {
        @Test
        @DisplayName("A 32-character message becomes 4 blocks of 64 bits")
        void fourBlocksOf64Bits() {
            int[][] blocks = AbstractBlockCipher.toBlocks(FULL_MESSAGE);
            assertEquals(4, blocks.length);
            for (int[] block : blocks) {
                assertEquals(64, block.length);
            }
        }

        @Test
        @DisplayName("Block 1 of \"Meet me ...\" is 4D656574206D6520 (spec test vector)")
        void firstBlockMatchesSpec() {
            int[][] blocks = AbstractBlockCipher.toBlocks(FULL_MESSAGE);
            assertEquals("4D656574206D6520", BitUtils.toHex(blocks[0]));
        }

        @Test
        @DisplayName("fromBlocks(toBlocks(m)) gives back m")
        void joinReversesSplit() {
            assertEquals(FULL_MESSAGE, AbstractBlockCipher.fromBlocks(AbstractBlockCipher.toBlocks(FULL_MESSAGE)));
        }

        @Test
        @DisplayName("Splitting a message that is not 32 characters is rejected")
        void splitRejectsWrongLength() {
            assertThrows(IllegalArgumentException.class, () -> AbstractBlockCipher.toBlocks("short"));
        }
    }

    @Nested
    @DisplayName("Ciphertext format (64 hex digits)")
    class CiphertextFormat {
        @Test
        @DisplayName("A ciphertext with the wrong length is rejected")
        void wrongLengthRejected() {
            assertThrows(IllegalArgumentException.class, () -> AbstractBlockCipher.validateCipherHex("ABC"));
            assertThrows(IllegalArgumentException.class, () -> AbstractBlockCipher.validateCipherHex(null));
        }

        @Test
        @DisplayName("A ciphertext with a non-hex character is rejected")
        void nonHexRejected() {
            String bad = "G" + "0".repeat(63);
            assertThrows(IllegalArgumentException.class, () -> AbstractBlockCipher.validateCipherHex(bad));
        }

        @Test
        @DisplayName("Unicode digits that are not 0-9/A-F are rejected (e.g. Arabic-Indic three)")
        void unicodeDigitRejected() {
            String bad = "\u0663" + "0".repeat(63);
            assertThrows(IllegalArgumentException.class, () -> AbstractBlockCipher.validateCipherHex(bad));
        }

        @Test
        @DisplayName("Lower-case hex is accepted")
        void lowerCaseAccepted() {
            assertDoesNotThrow(() -> AbstractBlockCipher.validateCipherHex("0123456789abcdef".repeat(4)));
        }

        @Test
        @DisplayName("64 hex digits are accepted")
        void validHexAccepted() {
            assertDoesNotThrow(() -> AbstractBlockCipher.validateCipherHex("0123456789ABCDEF".repeat(4)));
        }
    }

    @Nested
    @DisplayName("Whole pipeline (with the identity test cipher)")
    class Pipeline {
        @Test
        @DisplayName("encrypt returns 64 hex digits")
        void encryptReturns64Hex() throws Exception {
            assertEquals(64, cipher.encrypt(FULL_MESSAGE).length());
        }

        @Test
        @DisplayName("A short message survives encrypt + decrypt with the padding removed")
        void shortMessageRoundTrip() throws Exception {
            assertEquals("Hello", cipher.decrypt(cipher.encrypt("Hello")));
        }

        @Test
        @DisplayName("verifyRoundTrip (default method of Cipher) returns true")
        void verifyRoundTripWorks() throws Exception {
            assertTrue(cipher.verifyRoundTrip(FULL_MESSAGE));
        }

        @Test
        @DisplayName("encrypt rejects an invalid message, decrypt rejects an invalid ciphertext")
        void pipelineRejectsBadInput() {
            assertThrows(InvalidMessageException.class, () -> cipher.encrypt((String) null));
            assertThrows(IllegalArgumentException.class, () -> cipher.decrypt("not hex"));
        }
    }
}

/* Test results (JUnit 5):
PASS  Whole pipeline (with the identity test cipher) > A short message survives encrypt + decrypt with the padding removed
PASS  Whole pipeline (with the identity test cipher) > encrypt rejects an invalid message, decrypt rejects an invalid ciphertext
PASS  Whole pipeline (with the identity test cipher) > verifyRoundTrip (default method of Cipher) returns true
PASS  Whole pipeline (with the identity test cipher) > encrypt returns 64 hex digits
PASS  Ciphertext format (64 hex digits) > Unicode digits that are not 0-9/A-F are rejected (e.g. Arabic-Indic three)
PASS  Ciphertext format (64 hex digits) > Lower-case hex is accepted
PASS  Ciphertext format (64 hex digits) > A ciphertext with the wrong length is rejected
PASS  Ciphertext format (64 hex digits) > A ciphertext with a non-hex character is rejected
PASS  Ciphertext format (64 hex digits) > 64 hex digits are accepted
PASS  Segmentation into 4 blocks of 64 bits > Block 1 of "Meet me ..." is 4D656574206D6520 (spec test vector)
PASS  Segmentation into 4 blocks of 64 bits > fromBlocks(toBlocks(m)) gives back m
PASS  Segmentation into 4 blocks of 64 bits > Splitting a message that is not 32 characters is rejected
PASS  Segmentation into 4 blocks of 64 bits > A 32-character message becomes 4 blocks of 64 bits
PASS  Padding and unpadding > unpad keeps spaces the user typed (only the padding character is removed)
PASS  Padding and unpadding > unpad(pad(x)) gives back x
PASS  Padding and unpadding > pad does not change a message that already has 32 characters
PASS  Short messages are valid and get padded > prepare() leaves a 32-character message unchanged (no padding)
PASS  Short messages are valid and get padded > A message shorter than 32 characters is valid (no exception)
PASS  Short messages are valid and get padded > prepare() pads a short message to 32 characters with NUL
PASS  Short messages are valid and get padded > prepare() does not pad an invalid message: the error reaches the caller
PASS  Short messages are valid and get padded > A 1-character message is accepted and padded with 31 NULs
PASS  Validation of the input message > The boundary characters space (32) and ~ (126) are accepted
PASS  Validation of the input message > A message with a non-printable or non-ASCII character is rejected > "café"
PASS  Validation of the input message > A message with a non-printable or non-ASCII character is rejected > "año"
PASS  Validation of the input message > A message with a non-printable or non-ASCII character is rejected > "tab	here"
PASS  Validation of the input message > A message with a non-printable or non-ASCII character is rejected > "smile ☺"
PASS  Validation of the input message > A message with a non-printable or non-ASCII character is rejected > "nul\u0000inside"
PASS  Validation of the input message > A message with a non-printable or non-ASCII character is rejected > "del\u007f"
PASS  Validation of the input message > An empty message is rejected
PASS  Validation of the input message > A message longer than 32 characters is rejected
PASS  Validation of the input message > A message of 33 characters (one too many) is rejected
PASS  Validation of the input message > A null message is rejected
PASS  Validation of the input message > A message of exactly 32 printable characters is accepted
33 tests successful, 0 failed
*/
