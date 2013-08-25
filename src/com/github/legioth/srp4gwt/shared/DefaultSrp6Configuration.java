package com.github.legioth.srp4gwt.shared;

import java.math.BigInteger;
import java.util.Random;

import com.googlecode.gwt.crypto.bouncycastle.Digest;
import com.googlecode.gwt.crypto.bouncycastle.digests.SHA1Digest;
import com.googlecode.gwt.crypto.util.SecureRandom;

public class DefaultSrp6Configuration implements Srp6Configuration {
    /**
     * Precomputed safe 256-bit prime 'N', as decimal.
     */
    public static final BigInteger N_256 = new BigInteger(
            "125617018995153554710546479714086468244499594888726646874671447258204721048803");

    /**
     * Precomputed safe 512-bit prime 'N', as decimal.
     */
    public static final BigInteger N_512 = new BigInteger(
            "11144252439149533417835749556168991736939157778924947037200268358613863350040339017097790259154750906072491181606044774215413467851989724116331597513345603");

    /**
     * Precomputed safe 768-bit prime 'N', as decimal.
     */
    public static final BigInteger N_768 = new BigInteger(
            "1087179135105457859072065649059069760280540086975817629066444682366896187793570736574549981488868217843627094867924800342887096064844227836735667168319981288765377499806385489913341488724152562880918438701129530606139552645689583147");

    /**
     * Precomputed safe 1024-bit prime 'N', as decimal.
     */
    public static final BigInteger N_1024 = new BigInteger(
            "167609434410335061345139523764350090260135525329813904557420930309800865859473551531551523800013916573891864789934747039010546328480848979516637673776605610374669426214776197828492691384519453218253702788022233205683635831626913357154941914129985489522629902540768368409482248290641036967659389658897350067939");

    private static final BigInteger g = new BigInteger("2");

    @Override
    public BigInteger N() {
        return N_768;
    }

    @Override
    public BigInteger g() {
        return g;
    }

    @Override
    public Digest digest() {
        return new SHA1Digest();
    }

    @Override
    public SecureRandom random() {
        // TODO seed me!
        Random random = new Random();
        byte[] seed = new byte[1024];
        random.nextBytes(seed);
        return new SecureRandom(seed);
    }
}
