package com.github.legioth.srp4gwt.shared;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

import com.github.legioth.srp4gwt.bouncycastle.util.BigIntegers;
import com.googlecode.gwt.crypto.bouncycastle.CryptoException;
import com.googlecode.gwt.crypto.bouncycastle.Digest;
import com.googlecode.gwt.crypto.util.SecureRandom;

public class Srp6Util {

    public static BigInteger calculateK(Digest digest, BigInteger N,
            BigInteger g) {
        return hashPaddedPair(digest, N, N, g);
    }

    public static BigInteger calculateU(Digest digest, BigInteger N,
            BigInteger A, BigInteger B) {
        return hashPaddedPair(digest, N, A, B);
    }

    public static BigInteger calculateX(Digest digest, BigInteger N,
            byte[] salt, byte[] identity, byte[] password) {
        byte[] output = new byte[digest.getDigestSize()];

        digest.update(identity, 0, identity.length);
        digest.update((byte) ':');
        digest.update(password, 0, password.length);
        digest.doFinal(output, 0);

        digest.update(salt, 0, salt.length);
        digest.update(output, 0, output.length);
        digest.doFinal(output, 0);

        return new BigInteger(1, output);
    }

    public static BigInteger generatePrivateValue(Digest digest, BigInteger N,
            BigInteger g, SecureRandom random) {
        int minBits = Math.min(256, N.bitLength() / 2);
        BigInteger min = BigInteger.ONE.shiftLeft(minBits - 1);
        BigInteger max = N.subtract(BigInteger.ONE);

        return BigIntegers.createRandomInRange(min, max, random);
    }

    public static BigInteger validatePublicValue(BigInteger N, BigInteger val)
            throws CryptoException {
        val = val.mod(N);

        // Check that val % N != 0
        if (val.equals(BigInteger.ZERO)) {
            throw new CryptoException("Invalid public value: 0");
        }

        return val;
    }

    public static BigInteger calculateM1(Digest digest, BigInteger N,
            BigInteger g, byte[] username, byte[] salt, BigInteger A,
            BigInteger B, BigInteger S) {
        int padLength = (N.bitLength() + 7) / 8;

        // H(N)
        byte[] nHash = new byte[digest.getDigestSize()];
        byte[] nBytes = getPadded(N, padLength);
        digest.update(nBytes, 0, nBytes.length);
        digest.doFinal(nHash, 0);

        // H(g)
        byte[] gHash = new byte[digest.getDigestSize()];
        byte[] gBytes = getPadded(g, padLength);
        digest.update(gBytes, 0, gBytes.length);
        digest.doFinal(gHash, 0);

        // H(N) XOR H(g)
        byte[] ngHash = new byte[digest.getDigestSize()];
        for (int i = 0; i < gHash.length; i++) {
            ngHash[i] = (byte) (nHash[i] ^ gHash[i]);
        }

        // H(I)
        byte[] iHash = new byte[digest.getDigestSize()];
        digest.update(username, 0, username.length);
        digest.doFinal(iHash, 0);

        byte[] aBytes = getPadded(A, padLength);
        byte[] bBytes = getPadded(B, padLength);
        byte[] sBytes = getPadded(S, padLength);

        // H[H(N) XOR H(g) | H(I) | salt | A | B | S]
        digest.update(ngHash, 0, gHash.length);
        digest.update(iHash, 0, iHash.length);
        digest.update(salt, 0, salt.length);
        digest.update(aBytes, 0, aBytes.length);
        digest.update(bBytes, 0, bBytes.length);
        digest.update(sBytes, 0, sBytes.length);

        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);

        return new BigInteger(1, output);
    }

    private static BigInteger hashPaddedPair(Digest digest, BigInteger N,
            BigInteger n1, BigInteger n2) {
        int padLength = (N.bitLength() + 7) / 8;

        byte[] n1_bytes = getPadded(n1, padLength);
        byte[] n2_bytes = getPadded(n2, padLength);

        digest.update(n1_bytes, 0, n1_bytes.length);
        digest.update(n2_bytes, 0, n2_bytes.length);

        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);

        return new BigInteger(1, output);
    }

    private static byte[] getPadded(BigInteger n, int length) {
        byte[] bs = BigIntegers.asUnsignedByteArray(n);
        if (bs.length < length) {
            byte[] tmp = new byte[length];
            System.arraycopy(bs, 0, tmp, length - bs.length, bs.length);
            bs = tmp;
        }
        return bs;
    }

    public static BigInteger calculateM2(BigInteger N, Digest digest,
            BigInteger A, BigInteger M1, BigInteger S) {
        int padLength = (N.bitLength() + 7) / 8;

        byte[] bytes;

        bytes = getPadded(A, padLength);
        digest.update(bytes, 0, bytes.length);

        bytes = getPadded(M1, padLength);
        digest.update(bytes, 0, bytes.length);

        bytes = getPadded(S, padLength);
        digest.update(bytes, 0, bytes.length);

        bytes = new byte[digest.getDigestSize()];
        digest.doFinal(bytes, 0);

        BigInteger M2 = new BigInteger(1, bytes);

        return M2;
    }

    public static byte[] toByteArray(String string) {
        try {
            return string.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }
}
