package hbea;

/**
 * StudentConfig: the ONE place that holds the student's identity.
 *
 * <p>The assignment is individual and must use your own official e-mail as the
 * seed (Section 8). Every demo reads these constants, so changing these two lines
 * updates all the demos and screenshots at once.</p>
 */
public final class StudentConfig {

    private StudentConfig() { }

    /** Your official e-mail address: the key seed used in the demos. */
    public static final String EMAIL = "liglesias.ieu2024@student.ie.edu";

    /** Your first name: Task 4 encrypts a block that starts with it. */
    public static final String FIRST_NAME = "L";

    /** A different e-mail, used only for the wrong-key test (Task 5). */
    public static final String OTHER_EMAIL = "someone.else@student.ie.edu";
}

/* Output: constants only, no main method. */
