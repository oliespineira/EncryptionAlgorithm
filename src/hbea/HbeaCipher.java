package hbea;

public class HbeaCipher extends AbstractBlockCipher {
    @Override
    protected int[] encryptBlock(int[] block64) {
        throw new UnsupportedOperationException("HbeaCipher is not implemented yet (task 3).");
    }

    @Override
    protected int[] decryptBlock(int[] block64) {
        throw new UnsupportedOperationException("HbeaCipher is not implemented yet (task 5).");
    }

    @Override
    public String getName() {
        return "HBEA";
    }
}
