package com.github.legioth.srp4gwt.server;

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

/**
 * Implements the server side SRP-6a protocol. Note that this class is stateful,
 * and therefore NOT threadsafe. This implementation of SRP is based on the
 * optimized message sequence put forth by Thomas Wu in the paper
 * "SRP-6: Improvements and Refinements to the Secure Remote Password Protocol, 2002"
 */
public class Srp6Server {
    protected final BigInteger N;
    protected final BigInteger g;
    protected BigInteger v;

    protected final SecureRandom random;
    protected final Digest digest;

    protected BigInteger A;

    protected BigInteger b;
    protected BigInteger B;

    protected BigInteger u;
    protected BigInteger S;

    protected byte[] salt;
    private String identity;

    public Srp6Server(Srp6Configuration configuration) {
        this.N = configuration.N();
        this.g = configuration.g();

        this.random = configuration.random();
        this.digest = configuration.digest();
    }

    protected BigInteger selectPrivateValue() {
        return Srp6Util.generatePrivateValue(digest, N, g, random);
    }

    private BigInteger calculateS() {
        return v.modPow(u, N).multiply(A).mod(N).modPow(b, N);
    }

    public Srp6InitResponse getInitReponse(Srp6InitRequest initRequest,
            BigInteger v, String identity, byte[] salt) throws CryptoException {
        this.identity = identity;

        this.A = Srp6Util.validatePublicValue(N, initRequest.getA());
        this.v = v;
        this.salt = salt;

        BigInteger k = Srp6Util.calculateK(digest, N, g);
        this.b = selectPrivateValue();
        this.B = k.multiply(v).mod(N).add(g.modPow(b, N)).mod(N);

        return new Srp6InitResponse(salt, B);
    }

    public Srp6VerificationResponse getVerifyResponse(
            Srp6VerificationRequest verificationRequest) {
        this.u = Srp6Util.calculateU(digest, N, A, B);
        this.S = calculateS();

        BigInteger M1 = Srp6Util.calculateM1(digest, N, g,
                Srp6Util.toByteArray(identity), salt, A, B, S);

        if (!M1.equals(verificationRequest.getM1())) {
            // Failed verification, prevent key usage
            this.u = null;
            this.S = null;
            return null;
        } else {
            BigInteger M2 = Srp6Util.calculateM2(N, digest, A, M1, S);
            return new Srp6VerificationResponse(M2);
        }
    }

    public BigInteger getSecret() {
        return S;
    }

    public String getIdentity() {
        return identity;
    }

}
