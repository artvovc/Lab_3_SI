package com;

import java.math.BigInteger;
import java.security.SecureRandom;

public class DSA {
    private SecureRandom random = new SecureRandom();

    private BigInteger p;
    private BigInteger q;
    private BigInteger g;

    public DSA(BigInteger p, BigInteger q, BigInteger g) {
        this.p = p;
        this.q = q;
        this.g = g;
    }

    public BigInteger[] generateSignature(byte[] message, BigInteger x) {
        BigInteger m = calculateE(q, message);

        BigInteger k = nextK(q);

        BigInteger r = g.modPow(k, p).mod(q);

        k = k.modInverse(q).multiply(m.add(x.multiply(r)));

        BigInteger s = k.mod(q);

        return new BigInteger[]{r, s};
    }

    public boolean verifySignature(byte[] message, BigInteger[] sign, BigInteger y) {
        BigInteger m = calculateE(q, message);
        BigInteger zero = BigInteger.valueOf(0);

        BigInteger r = sign[0];
        BigInteger s = sign[1];

        if (zero.compareTo(r) >= 0 || q.compareTo(r) <= 0) {
            return false;
        }

        if (zero.compareTo(s) >= 0 || q.compareTo(s) <= 0) {
            return false;
        }

        BigInteger w = s.modInverse(q);

        BigInteger u1 = m.multiply(w).mod(q);
        BigInteger u2 = r.multiply(w).mod(q);

        u1 = g.modPow(u1, p);
        u2 = y.modPow(u2, p);

        BigInteger v = u1.multiply(u2).mod(p).mod(q);

        return v.equals(r);
    }

    private BigInteger calculateE(BigInteger n, byte[] message) {
        if (n.bitLength() >= message.length * 8) {
            return new BigInteger(1, message);
        } else {
            byte[] trunc = new byte[n.bitLength() / 8];

            System.arraycopy(message, 0, trunc, 0, trunc.length);

            return new BigInteger(1, trunc);
        }
    }

    private BigInteger nextK(BigInteger q) {
        int qBitLength = q.bitLength();

        BigInteger k;
        do {
            k = new BigInteger(qBitLength, random);
        } while (k.equals(BigInteger.valueOf(0)) || k.compareTo(q) >= 0);

        return k;
    }
}
