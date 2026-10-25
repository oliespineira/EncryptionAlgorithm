package hbea;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Task 2 - BDD tests for the SHA-256 key generation.
 *
 * Each @Nested class is one BDD scenario and each test is written as
 * Given (the situation) - When (the action) - Then (the expected result).
 * The DisplayNames make the scenarios readable in IntelliJ's test panel.
 */
@DisplayName("Feature: SHA-256 key generation")
class Sha256KeyGeneratorTest {

    private static final String OFFICIAL_EMAIL = "liglesias.ieu2024@student.ie.edu";

    /** Test vector from the spec: KS1 = 6C099BA0 (also used in BitUtilsTest). */
    private static final String VECTOR_EMAIL = "student@student.ie.edu";
    private static final String[] VECTOR_SEGMENTS = {
            "6C099BA0", "9261A2A3", "516842CB", "93139F39",
            "17514087", "47F298EF", "D359D5E8", "55D4B9F0"
    };

    private final Sha256KeyGenerator generator = new Sha256KeyGenerator();

    // ------------------------------------------------------------------
    @Nested
    @DisplayName("Scenario: a user generates a key from a valid email")
    class ValidEmail {

        @Test
        @DisplayName("Given a valid email, When the key is generated, Then it has 8 segments of 32 bits")
        void keyHasEightSegmentsOf32Bits() {
            // Given
            String email = OFFICIAL_EMAIL;
            // When
            int[][] key = generator.generateKeySegments(email);
            // Then
            assertEquals(KeyGenerator.SEGMENTS, key.length);
            for (int[] segment : key) {
                assertEquals(KeyGenerator.SEGMENT_BITS, segment.length);
            }
        }

        @Test
        @DisplayName("Given a valid email, When the key is generated, Then every value is a bit (0 or 1)")
        void everyValueIsABit() {
            // Given
            String email = OFFICIAL_EMAIL;
            // When
            int[][] key = generator.generateKeySegments(email);
            // Then
            for (int[] segment : key) {
                for (int bit : segment) {
                    assertTrue(bit == 0 || bit == 1, "Found a value that is not a bit: " + bit);
                }
            }
        }

        @Test
        @DisplayName("Given a valid email, When the key is generated, Then KS1..KS8 joined equal SHA-256 of the email")
        void segmentsJoinedEqualTheSha256Hash() throws Exception {
            // Given
            String email = OFFICIAL_EMAIL;
            byte[] reference = MessageDigest.getInstance("SHA-256")
                    .digest(email.getBytes(StandardCharsets.UTF_8));
            String expectedHex = HexFormat.of().withUpperCase().formatHex(reference);
            // When
            int[][] key = generator.generateKeySegments(email);
            // Then
            StringBuilder joined = new StringBuilder();
            for (int[] segment : key) {
                joined.append(BitUtils.toHex(segment));
            }
            assertEquals(expectedHex, joined.toString());
        }
    }

    // ------------------------------------------------------------------
    @Nested
    @DisplayName("Scenario: the generator matches the spec's test vector")
    class TestVector {

        @Test
        @DisplayName("Given the email student@student.ie.edu, When the key is generated, Then KS1..KS8 match the expected values")
        void matchesKnownSegments() {
            // Given
            String email = VECTOR_EMAIL;
            // When
            int[][] key = generator.generateKeySegments(email);
            // Then
            for (int i = 0; i < VECTOR_SEGMENTS.length; i++) {
                assertEquals(VECTOR_SEGMENTS[i], BitUtils.toHex(key[i]), "Wrong value for KS" + (i + 1));
            }
        }

        @Test
        @DisplayName("Given the test vector key, When KS1 is expanded with E, Then it gives the round key RK1 = 358053CF7D00")
        void ks1ExpandsToRoundKey1() {
            // Given
            int[] ks1 = generator.generateKeySegments(VECTOR_EMAIL)[0];
            // When
            int[] rk1 = BitUtils.permute(ks1, HbeaTables.e());
            // Then
            assertEquals("358053CF7D00", BitUtils.toHex(rk1));
        }
    }

    // ------------------------------------------------------------------
    @Nested
    @DisplayName("Scenario: the same user always gets the same key")
    class Reproducibility {

        @Test
        @DisplayName("Given the same email, When the key is generated twice, Then both keys are identical")
        void sameEmailSameKey() {
            // Given
            String email = OFFICIAL_EMAIL;
            // When
            int[][] first = generator.generateKeySegments(email);
            int[][] second = generator.generateKeySegments(email);
            // Then
            assertTrue(Arrays.deepEquals(first, second), "The same email produced two different keys");
        }

        @Test
        @DisplayName("Given two separate generator objects, When both generate a key for the same email, Then the keys are identical")
        void generatorIsStateless() {
            // Given
            KeyGenerator a = new Sha256KeyGenerator();
            KeyGenerator b = new Sha256KeyGenerator();
            // When
            int[][] keyA = a.generateKeySegments(OFFICIAL_EMAIL);
            int[][] keyB = b.generateKeySegments(OFFICIAL_EMAIL);
            // Then
            assertTrue(Arrays.deepEquals(keyA, keyB), "Two generators disagreed on the same email");
        }

        @Test
        @DisplayName("Given an email as a String and as UTF-8 bytes, When both overloads are used, Then the keys are identical")
        void stringAndByteOverloadsAgree() {
            // Given
            String email = OFFICIAL_EMAIL;
            byte[] emailBytes = email.getBytes(StandardCharsets.UTF_8);
            // When
            int[][] fromString = generator.generateKeySegments(email);
            int[][] fromBytes = generator.generateKeySegments(emailBytes);
            // Then
            assertTrue(Arrays.deepEquals(fromString, fromBytes), "The String and byte[] overloads disagree");
        }
    }

    // ------------------------------------------------------------------
    @Nested
    @DisplayName("Scenario: each user gets a unique key")
    class Uniqueness {

        @Test
        @DisplayName("Given two different emails, When their keys are generated, Then the keys are different")
        void differentEmailsDifferentKeys() {
            // Given
            String alice = OFFICIAL_EMAIL;
            String bob = VECTOR_EMAIL;
            // When
            int[][] keyAlice = generator.generateKeySegments(alice);
            int[][] keyBob = generator.generateKeySegments(bob);
            // Then
            assertFalse(Arrays.deepEquals(keyAlice, keyBob), "Two different emails produced the same key");
        }

        @Test
        @DisplayName("Given two emails that differ in one character, When their keys are generated, Then many bits change (avalanche effect)")
        void oneCharacterChangesManyBits() {
            // Given
            String original = "liglesias.ieu2024@student.ie.edu";
            String oneCharDifferent = "liglesias.ieu2025@student.ie.edu";
            // When
            int[][] k1 = generator.generateKeySegments(original);
            int[][] k2 = generator.generateKeySegments(oneCharDifferent);
            // Then: around half of the 256 bits should change (we accept 64..192)
            int differentBits = 0;
            for (int s = 0; s < KeyGenerator.SEGMENTS; s++) {
                for (int b = 0; b < KeyGenerator.SEGMENT_BITS; b++) {
                    if (k1[s][b] != k2[s][b]) {
                        differentBits++;
                    }
                }
            }
            assertTrue(differentBits >= 64 && differentBits <= 192,
                    "Only " + differentBits + " of 256 bits changed");
        }
    }

    // ------------------------------------------------------------------
    @Nested
    @DisplayName("Scenario: an invalid seed is rejected")
    class InvalidSeed {

        @ParameterizedTest(name = "seed = \"{0}\"")
        @NullAndEmptySource
        @ValueSource(strings = {" ", "   ", "\t", "\n"})
        @DisplayName("Given a null, empty or blank seed, When the key is generated, Then an IllegalArgumentException is thrown")
        void blankSeedIsRejected(String seed) {
            // Given: the seed from the parameter
            // When / Then
            assertThrows(IllegalArgumentException.class, () -> generator.generateKeySegments(seed));
        }

        @Test
        @DisplayName("Given null or empty bytes, When the byte[] overload is used, Then an IllegalArgumentException is thrown")
        void emptyBytesAreRejected() {
            // Given
            byte[] nothing = null;
            byte[] empty = new byte[0];
            // When / Then
            assertThrows(IllegalArgumentException.class, () -> generator.generateKeySegments(nothing));
            assertThrows(IllegalArgumentException.class, () -> generator.generateKeySegments(empty));
        }

        @Test
        @DisplayName("Given a bit array that is not 256 bits long, When it is segmented, Then an IllegalArgumentException is thrown")
        void wrongKeyLengthIsRejected() {
            // Given
            int[] tooShort = new int[128];
            // When / Then
            assertThrows(IllegalArgumentException.class, () -> Sha256KeyGenerator.segment(tooShort));
        }
    }

    // ------------------------------------------------------------------
    @Nested
    @DisplayName("Scenario: the key is handled securely")
    class SecureHandling {

        @Test
        @DisplayName("Given a key that a caller modifies, When the key is generated again, Then the new key is not affected")
        void eachCallReturnsAnIndependentCopy() {
            // Given
            int[][] first = generator.generateKeySegments(OFFICIAL_EMAIL);
            int originalBit = first[0][0];
            first[0][0] = 1 - originalBit;     // tamper with the returned array
            // When
            int[][] second = generator.generateKeySegments(OFFICIAL_EMAIL);
            // Then
            assertEquals(originalBit, second[0][0]);
        }

        @Test
        @DisplayName("Given a generated key, When it is wiped, Then every bit is 0")
        void wipeErasesTheKey() {
            // Given
            int[][] key = generator.generateKeySegments(OFFICIAL_EMAIL);
            // When
            Sha256KeyGenerator.wipe(key);
            // Then
            for (int[] segment : key) {
                assertArrayEquals(new int[KeyGenerator.SEGMENT_BITS], segment);
            }
        }

        @Test
        @DisplayName("Given no key (null), When wipe is called, Then nothing fails")
        void wipeAcceptsNull() {
            assertDoesNotThrow(() -> Sha256KeyGenerator.wipe(null));
        }
    }

    // ------------------------------------------------------------------
    @Nested
    @DisplayName("Scenario: the demo function verifies the key")
    class Demo {

        @Test
        @DisplayName("Given the official email, When the demo runs, Then it reports the key as verified")
        void demoVerifiesTheKey() throws Exception {
            // Given
            String email = OFFICIAL_EMAIL;
            // When
            boolean verified = KeyGenerationDemo.demo(email);
            // Then
            assertTrue(verified, "The demo could not verify the generated key");
        }
    }
}

/*
 * ===================== RUNNING RESULTS (Sha256KeyGeneratorTest) =====================
 * Feature: SHA-256 key generation                                  22 tests, 22 passed
 *   Scenario: a user generates a key from a valid email                    3/3 passed
 *   Scenario: the generator matches the spec's test vector                 2/2 passed
 *   Scenario: the same user always gets the same key                       3/3 passed
 *   Scenario: each user gets a unique key                                  2/2 passed
 *   Scenario: an invalid seed is rejected (6 parameterized + 2)            8/8 passed
 *   Scenario: the key is handled securely                                  3/3 passed
 *   Scenario: the demo function verifies the key                           1/1 passed
 * All tests in project (BitUtilsTest + Sha256KeyGeneratorTest):       37/37 passed
 * ====================================================================================
 */