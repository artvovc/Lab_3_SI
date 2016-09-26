package com;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Generator {
    private MessageDigest digest;
    private SecureRandom random = new SecureRandom();

    private static final BigInteger ZERO = BigInteger.valueOf(0);
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    public Generator() throws NoSuchAlgorithmException {
        digest = MessageDigest.getInstance("SHA-1");
    }

    public BigInteger[] generateParameters() {
        int n1 = 160;
        byte[] seed = new byte[20];
        int l = 1024;
        int n = (l - 1) / 160;
        int b = (l - 1) % 160;

        byte[] output;

        for (; ; ) {
            random.nextBytes(seed);

            output = digest.digest(seed);

            BigInteger U = new BigInteger(1, output).mod(ONE.shiftLeft(n1 - 1));

            BigInteger q = ONE.shiftLeft(n1 - 1).add(U).add(ONE).subtract(U.mod(TWO));

            int certainty = 80;
            if (!q.isProbablePrime(certainty)) {
                continue;
            }

            int counterLimit = 4 * l;
            for (int counter = 0; counter < counterLimit; ++counter) {
                BigInteger W = ZERO;
                for (int j = 0, exp = 0; j <= n; ++j, exp += 160) {
                    inc(seed);

                    output = digest.digest(seed);

                    BigInteger Vj = new BigInteger(1, output);
                    if (j == n) {
                        Vj = Vj.mod(ONE.shiftLeft(b));
                    }

                    W = W.add(Vj.shiftLeft(exp));
                }

                BigInteger X = W.add(ONE.shiftLeft(l - 1));

                BigInteger c = X.mod(q.shiftLeft(1));

                BigInteger p = X.subtract(c.subtract(ONE));

                if (p.bitLength() != l) {
                    continue;
                }

                if (p.isProbablePrime(certainty)) {
                    BigInteger g = calculateGenerator(p, q, random);

                    return new BigInteger[]{p, q, g};
                }
            }
        }
    }

    private BigInteger calculateGenerator(BigInteger p, BigInteger q, SecureRandom r) {
        BigInteger e = p.subtract(ONE).divide(q);
        BigInteger pSub2 = p.subtract(TWO);

        for (; ; ) {
            BigInteger h = new BigInteger(pSub2.subtract(ONE).bitLength() - 1, random).add(ONE);
            BigInteger g = h.modPow(e, p);
            if (g.bitLength() > 1) {
                return g;
            }
        }
    }

    public static BigInteger calculatePrivateKey(BigInteger q, SecureRandom random) {
        return new BigInteger(q.bitLength() + 64, random).mod(q.subtract(ONE)).add(ONE);
    }

    public static BigInteger calculatePublicKey(BigInteger p, BigInteger g, BigInteger x) {
        return g.modPow(x, p);
    }

    private static void inc(byte[] buf) {
        for (int i = buf.length - 1; i >= 0; --i) {
            byte b = (byte) ((buf[i] + 1) & 0xff);
            buf[i] = b;

            if (b != 0) {
                break;
            }
        }
    }
}
