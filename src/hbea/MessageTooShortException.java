package hbea;

public class MessageTooShortException extends InvalidMessageException {
    private final int actualLength;

    public MessageTooShortException(int actualLength, int requiredLength) {
        super("Message has " + actualLength + " characters; " + requiredLength
                + " are required. It will be padded.");
        this.actualLength = actualLength;
    }

    public int getActualLength() {
        return actualLength;
    }
}