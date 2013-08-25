package com.github.legioth.srp4gwt.shared;

import java.io.Serializable;
import java.math.BigInteger;

public class Srp6VerificationRequest implements Serializable {

    private BigInteger M1;

    public Srp6VerificationRequest() {

    }

    public Srp6VerificationRequest(BigInteger M1) {
        this.M1 = M1;
    }

    public void setM1(BigInteger M1) {
        this.M1 = M1;
    }

    public BigInteger getM1() {
        return M1;
    }

}
