package hbea;

public class XorCipher extends AbstractBlockCipher {
    @Override
    protected int[] encryptBlock(int[] block64) {
        throw new UnsupportedOperationException("XorCipher is not implemented yet.");
    }

    @Override
    protected int[] decryptBlock(int[] block64) {
        throw new UnsupportedOperationException("XorCipher is not implemented yet.");
    }

    @Override
    public String getName() {
        return "XOR";
    }
}
