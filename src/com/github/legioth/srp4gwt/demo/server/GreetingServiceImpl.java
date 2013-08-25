package com.github.legioth.srp4gwt.demo.server;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.http.HttpSession;

import com.github.legioth.srp4gwt.demo.client.GreetingService;
import com.github.legioth.srp4gwt.server.Srp6Server;
import com.github.legioth.srp4gwt.shared.DefaultSrp6Configuration;
import com.github.legioth.srp4gwt.shared.Srp6InitRequest;
import com.github.legioth.srp4gwt.shared.Srp6InitResponse;
import com.github.legioth.srp4gwt.shared.Srp6VerificationRequest;
import com.github.legioth.srp4gwt.shared.Srp6VerificationResponse;
import com.google.gwt.user.server.rpc.RemoteServiceServlet;
import com.googlecode.gwt.crypto.bouncycastle.CryptoException;

/**
 * The server side implementation of the RPC service.
 */
@SuppressWarnings("serial")
public class GreetingServiceImpl extends RemoteServiceServlet implements
        GreetingService {

    // Poor man's password storage
    private static final Map<String, byte[]> salts = new ConcurrentHashMap<String, byte[]>();
    private static final Map<String, BigInteger> verifiers = new ConcurrentHashMap<String, BigInteger>();

    @Override
    public void submitVerifier(String username, byte[] salt, BigInteger verifier) {
        System.out.println("Verifier submit for " + username);
        System.out.println("\tverifier: " + verifier.toString());
        System.out.println("\tSalt: " + Arrays.toString(salt));

        salts.put(username, salt);
        verifiers.put(username, verifier);
    }

    @Override
    public Srp6InitResponse init(Srp6InitRequest initRequest) {
        String username = initRequest.getIdentity();

        BigInteger v = verifiers.get(username);
        byte[] salt = salts.get(username);

        Srp6Server server = new Srp6Server(new DefaultSrp6Configuration());

        getThreadLocalRequest().getSession(true).setAttribute(
                "CurrentSRP6Server", server);

        if (v == null) {
            // Use dummy values if username is not found to avoid disclosing
            // that information
            v = BigInteger.valueOf(0);
            // TODO generate unique deterministic salt (based on some
            // server-side secret) to make it harder to check whether a username
            // exists.
            salt = new byte[0];
        }

        try {
            System.out.println("Got init request for user " + username);
            System.out.println("\tReturning salt  " + Arrays.toString(salt));

            return server.getInitReponse(initRequest, v, username, salt);
        } catch (CryptoException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Srp6VerificationResponse verify(
            Srp6VerificationRequest verificationRequest) {
        HttpSession session = getThreadLocalRequest().getSession(true);
        Srp6Server server = (Srp6Server) session
                .getAttribute("CurrentSRP6Server");

        Srp6VerificationResponse verifyResponse = server
                .getVerifyResponse(verificationRequest);

        if (verifyResponse == null) {
            System.out.println("Verification failed for "
                    + server.getIdentity());
        } else {
            System.out.println(server.getIdentity()
                    + " logged in with session key " + server.getSecret());
            System.out.println("Sending back M2 value "
                    + verifyResponse.getM2());
        }

        return verifyResponse;
    }

}
