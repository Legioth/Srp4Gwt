package com.github.legioth.srp4gwt.shared;

import java.io.Serializable;
import java.math.BigInteger;

public class Srp6VerificationResponse implements Serializable {

    private BigInteger M2;

    public Srp6VerificationResponse() {
        // GWT-RPC constructor
    }

    public Srp6VerificationResponse(BigInteger M2) {
        this.M2 = M2;
    }

    public void setM2(BigInteger M2) {
        this.M2 = M2;
    }

    public BigInteger getM2() {
        return M2;
    }

}
