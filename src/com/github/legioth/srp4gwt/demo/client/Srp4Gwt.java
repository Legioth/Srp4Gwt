package com.github.legioth.srp4gwt.demo.client;

import java.math.BigInteger;

import com.github.legioth.srp4gwt.client.Srp6Client;
import com.github.legioth.srp4gwt.shared.DefaultSrp6Configuration;
import com.github.legioth.srp4gwt.shared.Srp6Configuration;
import com.github.legioth.srp4gwt.shared.Srp6InitRequest;
import com.github.legioth.srp4gwt.shared.Srp6InitResponse;
import com.github.legioth.srp4gwt.shared.Srp6VerificationRequest;
import com.github.legioth.srp4gwt.shared.Srp6VerificationResponse;
import com.google.gwt.core.client.Duration;
import com.google.gwt.core.client.EntryPoint;
import com.google.gwt.core.client.GWT;
import com.google.gwt.dom.client.Style.WhiteSpace;
import com.google.gwt.event.dom.client.ClickEvent;
import com.google.gwt.event.dom.client.ClickHandler;
import com.google.gwt.user.client.rpc.AsyncCallback;
import com.google.gwt.user.client.ui.Button;
import com.google.gwt.user.client.ui.PasswordTextBox;
import com.google.gwt.user.client.ui.RootPanel;
import com.google.gwt.user.client.ui.TextArea;
import com.google.gwt.user.client.ui.TextBox;
import com.google.gwt.user.client.ui.VerticalPanel;
import com.googlecode.gwt.crypto.bouncycastle.CryptoException;

public class Srp4Gwt implements EntryPoint {
    private final GreetingServiceAsync greetingService = GWT
            .create(GreetingService.class);

    private final TextBox usernameField = new TextBox();
    private final PasswordTextBox passwordField = new PasswordTextBox();

    private final Srp6Configuration configuration = new DefaultSrp6Configuration();

    private TextArea logView = new TextArea();

    @Override
    public void onModuleLoad() {
        Button registerButton = new Button("Send verifier", new ClickHandler() {
            @Override
            public void onClick(ClickEvent event) {
                sendVerifier();
            }
        });
        Button authenticateButton = new Button("Authenticate",
                new ClickHandler() {
                    @Override
                    public void onClick(ClickEvent event) {
                        authenticate();
                    }
                });

        usernameField.setText("GWT User");

        logView.getElement().getStyle().setProperty("wordWrap", "normal");
        logView.getElement().getStyle().setWhiteSpace(WhiteSpace.PRE);
        logView.setReadOnly(true);
        logView.setHeight("20em");
        logView.setWidth("50em");

        VerticalPanel panel = new VerticalPanel();

        panel.add(usernameField);
        panel.add(passwordField);
        panel.add(registerButton);
        panel.add(authenticateButton);
        panel.add(logView);

        RootPanel rootPanel = RootPanel.get("gwt");
        rootPanel.add(panel);

        usernameField.setFocus(true);
        usernameField.selectAll();

        log("Using " + configuration.N().bitLength() + " bit prime: "
                + configuration.N());
    }

    private void log(String message) {
        message = Duration.currentTimeMillis() + ": " + message;

        logView.getElement().setInnerHTML(
                logView.getElement().getInnerHTML()
                        + message.replaceAll(" ", "&nbsp;") + "\n");

        // Scroll to the end
        logView.getElement().setScrollTop(Integer.MAX_VALUE);
    }

    private void sendVerifier() {
        // Initialize SRP handler
        Srp6Client verifierGenerator = new Srp6Client(configuration);

        byte[] salt = new byte[configuration.digest().getDigestSize()];
        configuration.random().nextBytes(salt);

        String username = usernameField.getText();
        String passowrd = passwordField.getText();

        Duration duration = new Duration();
        BigInteger verifier = verifierGenerator.generateVerifier(salt,
                username, passowrd);
        log("Verifier generated in " + duration.elapsedMillis() + " ms");

        log("Sending verifier to server: " + verifier);

        greetingService.submitVerifier(username, salt, verifier,
                new AsyncCallback<Void>() {

                    @Override
                    public void onFailure(Throwable caught) {
                        log("Error sending verifier: " + caught.getMessage());
                        caught.printStackTrace();
                    }

                    @Override
                    public void onSuccess(Void result) {
                        log("Verifier sent to the server");
                    }
                });

    }

    private void authenticate() {
        final Srp6Client client = new Srp6Client(configuration);

        log("Generating initialization request");

        Srp6InitRequest initRequest = client.generateInitRequest(usernameField
                .getText());

        log("Sening initialization request with A = " + initRequest.getA());

        greetingService.init(initRequest,
                new AsyncCallback<Srp6InitResponse>() {
                    @Override
                    public void onFailure(Throwable caught) {
                        log("Auhtentication initialization failed");
                    }

                    @Override
                    public void onSuccess(Srp6InitResponse initResponse) {
                        log("Got init response with B = " + initResponse.getB());
                        sendProof(client, initResponse);
                    }
                });

    }

    private void sendProof(final Srp6Client client, Srp6InitResponse result) {
        String password = passwordField.getText();
        try {
            Srp6VerificationRequest verificationRequest = client
                    .generateVerificationRequest(result, password);

            log("Sending verification request with M1 = "
                    + verificationRequest.getM1());

            greetingService.verify(verificationRequest,
                    new AsyncCallback<Srp6VerificationResponse>() {
                        @Override
                        public void onFailure(Throwable caught) {
                            log("Error validating m1. " + caught.getMessage());
                            caught.printStackTrace();
                        }

                        @Override
                        public void onSuccess(Srp6VerificationResponse response) {
                            if (response == null) {
                                log("Server did not accept the M1 value");
                            } else {
                                log("Got verification response with M2 = "
                                        + response.getM2());
                                BigInteger sessionKey = client
                                        .getSessionKey(response);
                                if (sessionKey != null) {
                                    log("Authentication completed with session key "
                                            + sessionKey);
                                } else {
                                    log("Final authentication verification failed");
                                }
                            }
                        }
                    });
        } catch (CryptoException e) {
            log("Could not calculate secret. " + e.getLocalizedMessage());
            e.printStackTrace();
        }
    }

}
