package hbea;

/**
 * InvalidMessageException: a <b>checked</b> exception for a message that cannot
 * be encrypted (null, empty, longer than 32 characters, or containing a
 * character outside printable ASCII 32-126).
 *
 * <p>Because it extends {@link Exception} (and not RuntimeException), the
 * compiler forces every caller either to catch it or to declare it with
 * {@code throws}. That is the difference between checked and unchecked
 * exceptions seen in class (Chapter 14).</p>
 */
public class InvalidMessageException extends Exception {

    /** Exceptions are Serializable; this version number avoids a compiler warning. */
    private static final long serialVersionUID = 1L;

    /** @param message a human-readable explanation of what is wrong */
    public InvalidMessageException(String message) {
        super(message);
    }

    /**
     * Chained-exception constructor: keeps the original cause.
     *
     * @param message a human-readable explanation
     * @param cause   the lower-level exception that triggered this one
     */
    public InvalidMessageException(String message, Throwable cause) {
        super(message, cause);
    }
}

/* Output: exception class, it has no main method. Example of it being thrown and
   caught (from Main):
Message (max 32 printable ASCII characters): café
  Invalid message: Invalid character 'é' at position 3: only printable ASCII (32-126) is allowed.
  Please try again.
*/
