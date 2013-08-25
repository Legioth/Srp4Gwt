package com.github.legioth.srp4gwt.demo.client;

import java.math.BigInteger;

import com.github.legioth.srp4gwt.shared.Srp6InitRequest;
import com.github.legioth.srp4gwt.shared.Srp6InitResponse;
import com.github.legioth.srp4gwt.shared.Srp6VerificationRequest;
import com.github.legioth.srp4gwt.shared.Srp6VerificationResponse;
import com.google.gwt.user.client.rpc.RemoteService;
import com.google.gwt.user.client.rpc.RemoteServiceRelativePath;

/**
 * The client side stub for the RPC service.
 */
@RemoteServiceRelativePath("greet")
public interface GreetingService extends RemoteService {
    void submitVerifier(String username, byte[] salt, BigInteger verifier);

    Srp6InitResponse init(Srp6InitRequest initRequest);

    Srp6VerificationResponse verify(Srp6VerificationRequest verificationRequest);

}
