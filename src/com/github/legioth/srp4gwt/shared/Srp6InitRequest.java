package com.github.legioth.srp4gwt.shared;

import java.io.Serializable;
import java.math.BigInteger;

public class Srp6InitRequest implements Serializable {
    private String identity;
    private BigInteger A;

    public Srp6InitRequest() {

    }

    public Srp6InitRequest(String identity, BigInteger A) {
        this.identity = identity;
        this.A = A;
    }

    public String getIdentity() {
        return identity;
    }

    public void setIdentity(String identity) {
        this.identity = identity;
    }

    public BigInteger getA() {
        return A;
    }

    public void setA(BigInteger A) {
        this.A = A;
    }

}
