package com.github.legioth.srp4gwt.shared;

import java.math.BigInteger;

import com.googlecode.gwt.crypto.bouncycastle.Digest;
import com.googlecode.gwt.crypto.util.SecureRandom;

public interface Srp6Configuration {
    public BigInteger N();

    public BigInteger g();

    public Digest digest();

    public SecureRandom random();
}
