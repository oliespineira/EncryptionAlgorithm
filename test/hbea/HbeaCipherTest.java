package hbea;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Encryption (HbeaCipher): unit tests per round")
class HbeaCipherTest {
    private static final String OFFICIAL_EMAIL = "liglesias.ieu2024@student.ie.edu";
    private static final String OLIVIA_EMAIL = "oespineira.ieu2024@student.ie.edu";
    private static final String VECTOR_EMAIL = "student@student.ie.edu";
    private static final String FULL_MESSAGE = "Meet me at the library at 5pm!!!";

    private static final String[] OLIVIA_ROUND_DEMO = {
            "3F080B3500FF1709",
            "00FF1709E7F402F4",
            "E7F402F4F44F9E6E",
            "F44F9E6E8BA0D670",
            "8BA0D6704065474E",
            "4065474E1B4E804E",
            "1B4E804EB13647AD",
            "B13647AD3FD76672",
            "3FD766726C9E90B5"
    };

    private static int[] block(String eightChars) {
        return BitUtils.bytesToBits(eightChars.getBytes(StandardCharsets.US_ASCII));
    }

    @Nested
    @DisplayName("Round keys: RK(i) = E(KS(i))")
    class RoundKeys {
        @Test
        @DisplayName("There are 8 round keys of 48 bits")
        void eightRoundKeysOf48Bits() {
            HbeaCipher cipher = new HbeaCipher(OFFICIAL_EMAIL);
            for (int round = 1; round <= HbeaCipher.ROUNDS; round++) {
                assertEquals(48, cipher.roundKey(round).length);
            }
        }

        @Test
        @DisplayName("Every round key is the expansion of the matching key segment")
        void roundKeysAreExpandedSegments() {
            HbeaCipher cipher = new HbeaCipher(OFFICIAL_EMAIL);
            int[][] segments = new Sha256KeyGenerator().generateKeySegments(OFFICIAL_EMAIL);
            for (int round = 1; round <= HbeaCipher.ROUNDS; round++) {
                int[] expected = BitUtils.permute(segments[round - 1], HbeaTables.e());
                assertArrayEquals(expected, cipher.roundKey(round), "Wrong round key " + round);
            }
        }

        @Test
        @DisplayName("RK1 for student@student.ie.edu is 358053CF7D00 (spec)")
        void roundKey1MatchesSpec() {
            assertEquals("358053CF7D00", BitUtils.toHex(new HbeaCipher(VECTOR_EMAIL).roundKey(1)));
        }

        @Test
        @DisplayName("Asking for a round outside 1..8 is rejected")
        void invalidRoundRejected() {
            HbeaCipher cipher = new HbeaCipher(OFFICIAL_EMAIL);
            assertThrows(IllegalArgumentException.class, () -> cipher.roundKey(0));
            assertThrows(IllegalArgumentException.class, () -> cipher.roundKey(9));
        }
    }

    @Nested
    @DisplayName("Each encryption round")
    class EachRound {
        @Test
        @DisplayName("After IP, block \"Meet me \" splits into L0 = 6F086F67 and R0 = 00FE2100 (spec)")
        void initialPermutationMatchesSpec() {
            int[][] states = new HbeaCipher(VECTOR_EMAIL).trace(block("Meet me "));
            assertEquals("6F086F6700FE2100", BitUtils.toHex(states[0]));
        }

        @Test
        @DisplayName("Round 1 of \"Meet me \" gives L1 = 00FE2100 and R1 = 0488C614 (spec)")
        void firstRoundMatchesSpec() {
            int[][] states = new HbeaCipher(VECTOR_EMAIL).trace(block("Meet me "));
            assertEquals("00FE21000488C614", BitUtils.toHex(states[1]));
        }

        @ParameterizedTest(name = "round {0}")
        @ValueSource(ints = {0, 1, 2, 3, 4, 5, 6, 7, 8})
        @DisplayName("Each round matches Olivia's RoundDemo (block \"olivia  \")")
        void eachRoundMatchesRoundDemo(int round) {
            int[][] states = new HbeaCipher(OLIVIA_EMAIL).trace(block("olivia  "));
            assertEquals(OLIVIA_ROUND_DEMO[round], BitUtils.toHex(states[round]));
        }

        @Test
        @DisplayName("In every round the new left half is the previous right half")
        void newLeftIsPreviousRight() {
            int[][] states = new HbeaCipher(OFFICIAL_EMAIL).trace(block("Meet me "));
            for (int round = 1; round <= HbeaCipher.ROUNDS; round++) {
                assertArrayEquals(Arrays.copyOfRange(states[round - 1], 32, 64),
                        Arrays.copyOfRange(states[round], 0, 32), "Round " + round);
            }
        }

        @Test
        @DisplayName("A block that is not 64 bits is rejected")
        void wrongBlockLengthRejected() {
            HbeaCipher cipher = new HbeaCipher(OFFICIAL_EMAIL);
            assertThrows(IllegalArgumentException.class, () -> cipher.trace(new int[32]));
        }
    }

    @Nested
    @DisplayName("Whole block: IP -> rounds -> swap -> IP^-1")
    class WholeBlock {
        @Test
        @DisplayName("With the 16 DES subkeys the structure gives the real DES ciphertext 85E813540F0AB405")
        void structureMatchesRealDes() {
            String[] desKeys = {
                    "1B02EFFC7072", "79AED9DBC9E5", "55FC8A42CF99", "72ADD6DB351D",
                    "7CEC07EB53A8", "63A53E507B2F", "EC84B7F618BC", "F78A3AC13BFB",
                    "E0DBEBEDE781", "B1F347BA464F", "215FD3DED386", "7571F59467E9",
                    "97C5D1FABA41", "5F43B7F2E73A", "BF918D3D3F0A", "CB3D8B0E17F5"
            };
            int[][] keys = new int[desKeys.length][];
            for (int i = 0; i < desKeys.length; i++) {
                keys[i] = BitUtils.fromHex(desKeys[i]);
            }
            int[] out = HbeaCipher.feistel(BitUtils.fromHex("0123456789ABCDEF"), keys, new DesRoundFunction());
            assertEquals("85E813540F0AB405", BitUtils.toHex(out));
        }

        @Test
        @DisplayName("The first letter of my name, L, encrypts to the same block as the steps done one by one")
        void firstLetterOfNameStepByStep() throws Exception {
            HbeaCipher cipher = new HbeaCipher(OFFICIAL_EMAIL);
            int[] plainBlock = AbstractBlockCipher.toBlocks(AbstractBlockCipher.pad("L"))[0];

            int[] x = BitUtils.permute(plainBlock, HbeaTables.ip());
            int[] left = Arrays.copyOfRange(x, 0, 32);
            int[] right = Arrays.copyOfRange(x, 32, 64);
            DesRoundFunction f = new DesRoundFunction();
            for (int round = 1; round <= HbeaCipher.ROUNDS; round++) {
                int[] newRight = BitUtils.xor(left, f.apply(right, cipher.roundKey(round)));
                left = right;
                right = newRight;
            }
            int[] preOutput = new int[64];
            System.arraycopy(right, 0, preOutput, 0, 32);
            System.arraycopy(left, 0, preOutput, 32, 32);
            String expectedBlock = BitUtils.toHex(BitUtils.permute(preOutput, HbeaTables.fp()));

            String ciphertext = cipher.encrypt("L");

            assertEquals(expectedBlock, ciphertext.substring(0, 16));
        }
    }

    @Nested
    @DisplayName("Encrypting a message")
    class EncryptMessage {
        @Test
        @DisplayName("The ciphertext has 64 hex digits")
        void ciphertextHas64HexDigits() throws Exception {
            String ciphertext = new HbeaCipher(OFFICIAL_EMAIL).encrypt(FULL_MESSAGE);
            assertEquals(64, ciphertext.length());
            assertTrue(ciphertext.matches("[0-9A-F]{64}"));
        }

        @Test
        @DisplayName("The ciphertext is different from the plaintext")
        void ciphertextDiffersFromPlaintext() throws Exception {
            String ciphertext = new HbeaCipher(OFFICIAL_EMAIL).encrypt(FULL_MESSAGE);
            String plainHex = BitUtils.toHex(BitUtils.bytesToBits(FULL_MESSAGE.getBytes(StandardCharsets.US_ASCII)));
            assertNotEquals(plainHex, ciphertext);
        }

        @Test
        @DisplayName("The same message and key always give the same ciphertext")
        void encryptionIsDeterministic() throws Exception {
            assertEquals(new HbeaCipher(OFFICIAL_EMAIL).encrypt(FULL_MESSAGE),
                    new HbeaCipher(OFFICIAL_EMAIL).encrypt(FULL_MESSAGE));
        }

        @Test
        @DisplayName("A different key gives a different ciphertext")
        void differentKeyDifferentCiphertext() throws Exception {
            assertNotEquals(new HbeaCipher(OFFICIAL_EMAIL).encrypt(FULL_MESSAGE),
                    new HbeaCipher(OLIVIA_EMAIL).encrypt(FULL_MESSAGE));
        }

        @Test
        @DisplayName("An invalid message is rejected before encrypting")
        void invalidMessageRejected() {
            HbeaCipher cipher = new HbeaCipher(OFFICIAL_EMAIL);
            assertThrows(InvalidMessageException.class, () -> cipher.encrypt(""));
        }

        @Test
        @DisplayName("HbeaCipher can be used through the Cipher interface")
        void usableThroughInterface() throws Exception {
            Cipher cipher = new HbeaCipher(OFFICIAL_EMAIL);
            assertEquals("HBEA", cipher.getName());
            assertEquals(64, cipher.encrypt("Hello").length());
        }

        @Test
        @DisplayName("A missing key generator or round function is rejected")
        void missingPartsRejected() {
            assertThrows(IllegalArgumentException.class,
                    () -> new HbeaCipher(OFFICIAL_EMAIL, null, new DesRoundFunction()));
            assertThrows(IllegalArgumentException.class,
                    () -> new HbeaCipher(OFFICIAL_EMAIL, new Sha256KeyGenerator(), null));
        }
    }
}

