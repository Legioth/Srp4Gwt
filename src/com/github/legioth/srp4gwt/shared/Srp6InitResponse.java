package com.github.legioth.srp4gwt.shared;

import java.io.Serializable;
import java.math.BigInteger;

public class Srp6InitResponse implements Serializable {
    private byte[] salt;
    private BigInteger B;

    public Srp6InitResponse() {
        // GWT-RPC constructor
    }

    public Srp6InitResponse(byte[] salt, BigInteger b) {
        super();
        this.salt = salt;
        B = b;
    }

    public byte[] getSalt() {
        return salt;
    }

    public BigInteger getB() {
        return B;
    }
}
