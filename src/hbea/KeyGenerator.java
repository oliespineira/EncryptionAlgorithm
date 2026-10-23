package hbea;

public interface KeyGenerator {
    int SEGMENTS = 8; // interface constants are public static final
    int SEGMENT_BITS = 32;
    int[][] generateKeySegments(String seed); // 8 x 32 bits
}