package com.github.legioth.srp4gwt.client;

import java.math.BigInteger;

import com.github.legioth.srp4gwt.shared.Srp6Configuration;
import com.github.legioth.srp4gwt.shared.Srp6InitRequest;
import com.github.legioth.srp4gwt.shared.Srp6InitResponse;
import com.github.legioth.srp4gwt.shared.Srp6Util;
import com.github.legioth.srp4gwt.shared.Srp6VerificationRequest;
import com.github.legioth.srp4gwt.shared.Srp6VerificationResponse;
import com.googlecode.gwt.crypto.bouncycastle.CryptoException;
import com.googlecode.gwt.crypto.bouncycastle.Digest;
import com.googlecode.gwt.crypto.util.SecureRandom;

public class Srp6Client {
    protected final BigInteger N;
    protected final BigInteger g;

    protected BigInteger a;
    protected BigInteger A;

    protected BigInteger B;

    protected BigInteger x;
    protected BigInteger u;
    protected BigInteger S;

    protected final Digest digest;
    protected final SecureRandom random;

    protected String identity;

    protected BigInteger M1;
    private byte[] salt;

    public Srp6Client(Srp6Configuration configuration) {
        N = configuration.N();
        g = configuration.g();
        digest = configuration.digest();
        random = configuration.random();
    }

    public Srp6InitRequest generateInitRequest(String identity) {
        this.identity = identity;

        a = Srp6Util.generatePrivateValue(digest, N, g, random);
        A = modPow(g, a, N);

        return new Srp6InitRequest(identity, A);
    }

    private BigInteger calculateS() {
        BigInteger k = Srp6Util.calculateK(digest, N, g);
        BigInteger exp = u.multiply(x).add(a);
        BigInteger tmp = modPow(g, x, N).multiply(k).mod(N);

        return modPow(B.subtract(tmp).mod(N), exp, N);
    }

    private static BigInteger modPow(BigInteger b, BigInteger e, BigInteger n) {
        // Use native js implementation for performance, pass data as hex
        // strings
        return new BigInteger(doModPow(b.toString(16), e.toString(16),
                n.toString(16)), 16);
    }

    private native static String doModPow(String b, String e, String n)
    /*-{
		return new $wnd.BigInteger(b, 16).modPow(new $wnd.BigInteger(e, 16),
				new $wnd.BigInteger(n, 16)).toString(16);
    }-*/;

    public Srp6VerificationRequest generateVerificationRequest(
            Srp6InitResponse result, String password) throws CryptoException {

        B = Srp6Util.validatePublicValue(N, result.getB());

        byte[] identityBytes = Srp6Util.toByteArray(identity);

        salt = result.getSalt();

        x = Srp6Util.calculateX(digest, N, salt, identityBytes,
                Srp6Util.toByteArray(password));

        u = Srp6Util.calculateU(digest, N, A, B);

        S = calculateS();

        M1 = Srp6Util.calculateM1(digest, N, g, identityBytes, salt, A, B, S);

        return new Srp6VerificationRequest(M1);
    }

    public BigInteger getSessionKey(Srp6VerificationResponse response) {
        BigInteger serverM2 = response.getM2();

        BigInteger M2 = Srp6Util.calculateM2(N, digest, A, M1, S);

        if (M2.equals(serverM2)) {
            return S;
        } else {
            return null;
        }
    }

    public BigInteger generateVerifier(byte[] salt, String identity,
            String password) {
        BigInteger x = Srp6Util.calculateX(digest, N, salt,
                Srp6Util.toByteArray(identity), Srp6Util.toByteArray(password));

        return modPow(g, x, N);
    }

}
