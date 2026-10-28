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

/** Task 2 (BDD): Given-When-Then scenarios for SHA-256 key generation. */
@DisplayName("Feature: SHA-256 key generation")
class Sha256KeyGeneratorTest {
    private static final String OFFICIAL_EMAIL = StudentConfig.EMAIL;

    private static final String VECTOR_EMAIL = "student@student.ie.edu";
    private static final String[] VECTOR_SEGMENTS = {
            "6C099BA0", "9261A2A3", "516842CB", "93139F39",
            "17514087", "47F298EF", "D359D5E8", "55D4B9F0"
    };

    private final KeyGenerator generator = new Sha256KeyGenerator();

    @Nested
    @DisplayName("Scenario: a user generates a key from a valid email")
    class ValidEmail {
        @Test
        @DisplayName("Given a valid email, When the key is generated, Then it has 8 segments of 32 bits")
        void keyHasEightSegmentsOf32Bits() {
            String email = OFFICIAL_EMAIL;

            int[][] key = generator.generateKeySegments(email);

            assertEquals(KeyGenerator.SEGMENTS, key.length);
            for (int[] segment : key) {
                assertEquals(KeyGenerator.SEGMENT_BITS, segment.length);
            }
        }

        @Test
        @DisplayName("Given a valid email, When the key is generated, Then every value is a bit (0 or 1)")
        void everyValueIsABit() {
            String email = OFFICIAL_EMAIL;

            int[][] key = generator.generateKeySegments(email);

            for (int[] segment : key) {
                for (int bit : segment) {
                    assertTrue(bit == 0 || bit == 1, "Found a value that is not a bit: " + bit);
                }
            }
        }

        @Test
        @DisplayName("Given a valid email, When the key is generated, Then KS1..KS8 joined equal SHA-256 of the email")
        void segmentsJoinedEqualTheSha256Hash() throws Exception {
            String email = OFFICIAL_EMAIL;
            byte[] reference = MessageDigest.getInstance("SHA-256")
                    .digest(email.getBytes(StandardCharsets.UTF_8));
            String expectedHex = HexFormat.of().withUpperCase().formatHex(reference);

            int[][] key = generator.generateKeySegments(email);

            StringBuilder joined = new StringBuilder();
            for (int[] segment : key) {
                joined.append(BitUtils.toHex(segment));
            }
            assertEquals(expectedHex, joined.toString());
        }
    }

    @Nested
    @DisplayName("Scenario: the generator matches the spec's test vector")
    class TestVector {
        @Test
        @DisplayName("Given the seed student@student.ie.edu, When the key is generated, Then KS1 is 6C099BA0 and KS1..KS8 match Section 7")
        void matchesKnownSegments() {
            String email = VECTOR_EMAIL;

            int[][] key = generator.generateKeySegments(email);

            for (int i = 0; i < VECTOR_SEGMENTS.length; i++) {
                assertEquals(VECTOR_SEGMENTS[i], BitUtils.toHex(key[i]), "Wrong value for KS" + (i + 1));
            }
        }

        @Test
        @DisplayName("Given the test vector key, When KS1 is expanded with E, Then it gives the round key RK1 = 358053CF7D00")
        void ks1ExpandsToRoundKey1() {
            int[] ks1 = generator.generateKeySegments(VECTOR_EMAIL)[0];

            int[] rk1 = BitUtils.permute(ks1, HbeaTables.e());

            assertEquals("358053CF7D00", BitUtils.toHex(rk1));
        }
    }

    @Nested
    @DisplayName("Scenario: the email is normalised before hashing")
    class Normalisation {
        @Test
        @DisplayName("Given \" Student@Student.IE.edu \" (spaces, capitals), When the key is generated, Then the same key is produced (Task 2 spec scenario)")
        void specNormalisationScenario() {
            int[][] messy = generator.generateKeySegments(" Student@Student.IE.edu ");
            assertEquals("6C099BA0", BitUtils.toHex(messy[0]));
            assertTrue(Arrays.deepEquals(generator.generateKeySegments(VECTOR_EMAIL), messy));
        }

        @Test
        @DisplayName("Given a Turkish default locale, When an upper-case e-mail is normalised, Then the key is still the same")
        void localeDoesNotChangeTheKey() {
            java.util.Locale original = java.util.Locale.getDefault();
            try {
                java.util.Locale.setDefault(java.util.Locale.forLanguageTag("tr-TR"));
                int[][] turkish = generator.generateKeySegments("STUDENT@STUDENT.IE.EDU");
                assertEquals("6C099BA0", BitUtils.toHex(turkish[0]));
            } finally {
                java.util.Locale.setDefault(original);   // finally: always restore, even if the test fails
            }
        }

        @Test
        @DisplayName("Given the same email with capitals and surrounding spaces, When the key is generated, Then it equals the key of the plain email")
        void capitalsAndSpacesGiveTheSameKey() {
            String messy = "  " + OFFICIAL_EMAIL.toUpperCase(java.util.Locale.ROOT) + " ";

            int[][] fromMessy = generator.generateKeySegments(messy);
            int[][] fromPlain = generator.generateKeySegments(OFFICIAL_EMAIL);

            assertTrue(Arrays.deepEquals(fromPlain, fromMessy), "Normalisation did not remove case/spaces");
        }
    }

    @Nested
    @DisplayName("Scenario: the same user always gets the same key")
    class Reproducibility {
        @Test
        @DisplayName("Given the same email, When the key is generated twice, Then both keys are identical")
        void sameEmailSameKey() {
            String email = OFFICIAL_EMAIL;

            int[][] first = generator.generateKeySegments(email);
            int[][] second = generator.generateKeySegments(email);

            assertTrue(Arrays.deepEquals(first, second), "The same email produced two different keys");
        }

        @Test
        @DisplayName("Given two separate generator objects, When both generate a key for the same email, Then the keys are identical")
        void generatorIsStateless() {
            KeyGenerator a = new Sha256KeyGenerator();
            KeyGenerator b = new Sha256KeyGenerator();

            int[][] keyA = a.generateKeySegments(OFFICIAL_EMAIL);
            int[][] keyB = b.generateKeySegments(OFFICIAL_EMAIL);

            assertTrue(Arrays.deepEquals(keyA, keyB), "Two generators disagreed on the same email");
        }
    }

    @Nested
    @DisplayName("Scenario: each user gets a unique key")
    class Uniqueness {
        @Test
        @DisplayName("Given two different emails, When their keys are generated, Then the keys are different")
        void differentEmailsDifferentKeys() {
            String alice = OFFICIAL_EMAIL;
            String bob = VECTOR_EMAIL;

            int[][] keyAlice = generator.generateKeySegments(alice);
            int[][] keyBob = generator.generateKeySegments(bob);

            assertFalse(Arrays.deepEquals(keyAlice, keyBob), "Two different emails produced the same key");
        }

        @Test
        @DisplayName("Given two emails that differ in one character, When their keys are generated, Then many bits change (avalanche effect)")
        void oneCharacterChangesManyBits() {
            String original = "student2024@student.ie.edu";
            String oneCharDifferent = "student2025@student.ie.edu";

            int[][] k1 = generator.generateKeySegments(original);
            int[][] k2 = generator.generateKeySegments(oneCharDifferent);

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

    @Nested
    @DisplayName("Scenario: an invalid seed is rejected")
    class InvalidSeed {
        @ParameterizedTest(name = "seed = \"{0}\"")
        @NullAndEmptySource
        @ValueSource(strings = {" ", "   ", "\t", "\n"})
        @DisplayName("Given a null, empty or blank seed, When the key is generated, Then an IllegalArgumentException is thrown")
        void blankSeedIsRejected(String seed) {
            assertThrows(IllegalArgumentException.class, () -> generator.generateKeySegments(seed));
        }
    }

    @Nested
    @DisplayName("Scenario: each caller gets its own copy of the key")
    class IndependentCopies {
        @Test
        @DisplayName("Given a key that a caller modifies, When the key is generated again, Then the new key is not affected")
        void eachCallReturnsAnIndependentCopy() {
            int[][] first = generator.generateKeySegments(OFFICIAL_EMAIL);
            int originalBit = first[0][0];
            first[0][0] = 1 - originalBit;

            int[][] second = generator.generateKeySegments(OFFICIAL_EMAIL);

            assertEquals(originalBit, second[0][0]);
        }
    }

    @Nested
    @DisplayName("Scenario: the demo function verifies the key")
    class Demo {
        @Test
        @DisplayName("Given the official email, When the demo runs, Then it reports the key as verified")
        void demoVerifiesTheKey() throws Exception {
            String email = OFFICIAL_EMAIL;

            boolean verified = KeyGenerationDemo.demo(email);

            assertTrue(verified, "The demo could not verify the generated key");
        }
    }
}

/* Test results (JUnit 5):
PASS  Scenario: the demo function verifies the key > Given the official email, When the demo runs, Then it reports the key as verified
PASS  Scenario: each caller gets its own copy of the key > Given a key that a caller modifies, When the key is generated again, Then the new key is not affected
PASS  Scenario: an invalid seed is rejected > Given a null, empty or blank seed, When the key is generated, Then an IllegalArgumentException is thrown > seed = "null"
PASS  Scenario: an invalid seed is rejected > Given a null, empty or blank seed, When the key is generated, Then an IllegalArgumentException is thrown > seed = ""
PASS  Scenario: an invalid seed is rejected > Given a null, empty or blank seed, When the key is generated, Then an IllegalArgumentException is thrown > seed = " "
PASS  Scenario: an invalid seed is rejected > Given a null, empty or blank seed, When the key is generated, Then an IllegalArgumentException is thrown > seed = "   "
PASS  Scenario: an invalid seed is rejected > Given a null, empty or blank seed, When the key is generated, Then an IllegalArgumentException is thrown > seed = "	"
PASS  Scenario: each user gets a unique key > Given two emails that differ in one character, When their keys are generated, Then many bits change (avalanche effect)
PASS  Scenario: each user gets a unique key > Given two different emails, When their keys are generated, Then the keys are different
PASS  Scenario: the same user always gets the same key > Given the same email, When the key is generated twice, Then both keys are identical
PASS  Scenario: the same user always gets the same key > Given two separate generator objects, When both generate a key for the same email, Then the keys are identical
PASS  Scenario: the email is normalised before hashing > Given a Turkish default locale, When an upper-case e-mail is normalised, Then the key is still the same
PASS  Scenario: the email is normalised before hashing > Given " Student@Student.IE.edu " (spaces, capitals), When the key is generated, Then the same key is produced (Task 2 spec scenario)
PASS  Scenario: the email is normalised before hashing > Given the same email with capitals and surrounding spaces, When the key is generated, Then it equals the key of the plain email
PASS  Scenario: the generator matches the spec's test vector > Given the seed student@student.ie.edu, When the key is generated, Then KS1 is 6C099BA0 and KS1..KS8 match Section 7
PASS  Scenario: the generator matches the spec's test vector > Given the test vector key, When KS1 is expanded with E, Then it gives the round key RK1 = 358053CF7D00
PASS  Scenario: a user generates a key from a valid email > Given a valid email, When the key is generated, Then it has 8 segments of 32 bits
PASS  Scenario: a user generates a key from a valid email > Given a valid email, When the key is generated, Then KS1..KS8 joined equal SHA-256 of the email
PASS  Scenario: a user generates a key from a valid email > Given a valid email, When the key is generated, Then every value is a bit (0 or 1)
19 tests successful, 0 failed
*/
