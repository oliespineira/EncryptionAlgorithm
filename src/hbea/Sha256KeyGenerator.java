package hbea;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Locale;

/**
 * Sha256KeyGenerator: Step 1 of HBEA (Section 4.2).
 * seed -> trim + lower case -> SHA-256 -> 8 key segments of 32 bits.
 *
 * <p>Concepts shown: implementing an interface, using its constants
 * (SEGMENTS, SEGMENT_BITS), and turning a checked exception
 * (NoSuchAlgorithmException) into an unchecked one while keeping the original as
 * its <b>cause</b> (exception chaining).</p>
 */
public class Sha256KeyGenerator implements KeyGenerator {

    @Override
    public int[][] generateKeySegments(String seed) {
        if (seed == null) {
            throw new IllegalArgumentException("Key seed must not be null.");
        }
        if (seed.isBlank()) {
            throw new IllegalArgumentException("Key seed must not be empty or only whitespace.");
        }

        // 1. Normalise the seed: trim spaces + lower case.
        //    Locale.ROOT matters: with a Turkish locale, "I".toLowerCase() gives a dotless
        //    'ı', so the same e-mail would produce a completely different key.
        String normalised = seed.trim().toLowerCase(Locale.ROOT);

        // 2. SHA-256 of its UTF-8 bytes -> 32 bytes = 256 bits
        byte[] hash;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            hash = md.digest(normalised.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
        int[] keyBits = BitUtils.bytesToBits(hash);

        // 3. Split into 8 consecutive slices of 32 bits (KS1 = first 32 bits)
        int[][] segments = new int[SEGMENTS][];
        for (int i = 0; i < SEGMENTS; i++) {
            segments[i] = Arrays.copyOfRange(keyBits, i * SEGMENT_BITS, (i + 1) * SEGMENT_BITS);
        }
        return segments;
    }
}

/* Output: no main method. See KeyGenerationDemo.java for a run, and
   Sha256KeyGeneratorTest (BDD scenarios) for its tests:
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
