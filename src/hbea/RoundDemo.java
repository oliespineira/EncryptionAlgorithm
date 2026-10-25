package hbea;

import java.nio.charset.StandardCharsets; //this method lets us turn text into bytes using ASCII
import java.util.Arrays; // gives us copyOfRange for cutting the array into pieces.

/** Task 4 demo: encrypt one block starting with my name, printing L and R after each round. */
public class RoundDemo {

    public static void main(String[] args) {
        String name = "olivia";//this is what is going to be scrambled
        String seed = "oespineira.ieu2024@student.ie.edu";// this is the password the key is made from

        // Make an 8-character block (64 bits): pad with spaces or cut to 8
        String text = (name + "        ").substring(0, 8);// adds 8 spaces to the end,so the text is always long enough. and then we only keep the first 8 characters.
        int[] block = BitUtils.bytesToBits(text.getBytes(StandardCharsets.US_ASCII));// turn letters into numbers (for example m is 77) and then these numbers are turned into bits (77 is now 01001101)
        System.out.println("Block \"" + text + "\" = " + BitUtils.toHex(block));// printing text and its 64 bits written in hex(which makes it a shorter output)


        // creating the helpers to make the key
        KeyGenerator keyGen = new Sha256KeyGenerator();// this is the key maker. this takes in the interface KeyGenerator not the class as long as its something that can make keys its perfect
        RoundFunction f = new DesRoundFunction();// creates the mixer
        int[][] segments = keyGen.generateKeySegments(seed);// making the key: the email becomes 8 pieces of 32 bits with 8 rows, each holding 32 bits.

        // Initial permutation, then split into L0 and R0. shuffle and then cut it in half
        int[] x = BitUtils.permute(block, HbeaTables.ip());// shuffles the 64 bits using the IP table. this is the 'Initial permutation'
        int[] left = Arrays.copyOfRange(x, 0, 32);// copies the first 32 bits into the left half of L0
        int[] right = Arrays.copyOfRange(x, 32, 64);//copies the seconf 32 bits into the right half
        System.out.println("Round 0: L = " + BitUtils.toHex(left) + "  R = " + BitUtils.toHex(right));

        // 8 Feistel rounds
        for (int i = 0; i < 8; i++) {
            int[] roundKey = BitUtils.permute(segments[i], HbeaTables.e());   // RK(i) = E(KS(i)). make the jey for this round
            int[] newRight = BitUtils.xor(left, f.apply(right, roundKey));    // R(i) = L(i-1) XOR F(...). calculate the new right half
            left = right;   //move the halves                                 // L(i) = R(i-1)
            right = newRight;
            System.out.println("Round " + (i + 1) + ": L = " + BitUtils.toHex(left)
                    + "  R = " + BitUtils.toHex(right));
        }
    }
}

/* Output:
   Block "olivia  " = 6F6C697669612020
Round 0: L = 3F080B35  R = 00FF1709
Round 1: L = 00FF1709  R = E7F402F4
Round 2: L = E7F402F4  R = F44F9E6E
Round 3: L = F44F9E6E  R = 8BA0D670
Round 4: L = 8BA0D670  R = 4065474E
Round 5: L = 4065474E  R = 1B4E804E
Round 6: L = 1B4E804E  R = B13647AD
Round 7: L = B13647AD  R = 3FD76672
Round 8: L = 3FD76672  R = 6C9E90B5

*/