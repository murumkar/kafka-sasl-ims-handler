package com.manoj.security;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallback;
import org.apache.kafka.common.security.oauthbearer.internals.unsecured.OAuthBearerValidationResult;
import org.apache.kafka.common.utils.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.Arrays;

public class IMSAuthenticateValidatorCallbackHandler implements AuthenticateCallbackHandler {
    private final Logger log = LoggerFactory.getLogger(IMSAuthenticateValidatorCallbackHandler.class);
    private Map < String, String > moduleOptions = null;
    private boolean configured = false;
    private Time time = Time.SYSTEM;

    //Allowed scopes
    private static final String GLOBAL_SCOPE = "Global";
    private static final String APP_SCOPE = "MyAppScope";
    private static final String[] ALLOWED_SCOPES = new String[] {
            GLOBAL_SCOPE,
            APP_SCOPE
    };

    @Override
    public void configure(Map < String, ? > map, String saslMechanism, List < AppConfigurationEntry > jaasConfigEntries) {
        if (!OAuthBearerLoginModule.OAUTHBEARER_MECHANISM.equals(saslMechanism))
            throw new IllegalArgumentException(String.format("Unexpected SASL mechanism: %s", saslMechanism));
        if (Objects.requireNonNull(jaasConfigEntries).size() < 1 || jaasConfigEntries.get(0) == null)
            throw new IllegalArgumentException(
                    String.format("Must supply exactly 1 non-null JAAS mechanism configuration (size was %d)",
                            jaasConfigEntries.size()));
        this.moduleOptions = Collections.unmodifiableMap((Map < String, String > ) jaasConfigEntries.get(0).getOptions());
        configured = true;
    }

    public boolean isConfigured() {
        return this.configured;
    }

    @Override
    public void close() {}

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (!isConfigured())
            throw new IllegalStateException("Callback handler not configured");
        for (Callback callback: callbacks) {
            if (callback instanceof OAuthBearerValidatorCallback)
                try {
                    OAuthBearerValidatorCallback validationCallback = (OAuthBearerValidatorCallback) callback;
                    handleCallback(validationCallback);
                } catch (KafkaException e) {
                    throw new IOException(e.getMessage(), e);
                }
            else
                throw new UnsupportedCallbackException(callback);
        }
    }

    private void handleCallback(OAuthBearerValidatorCallback callback)
            throws IllegalArgumentException {
        String accessToken = callback.tokenValue();
        if (accessToken == null)
            throw new IllegalArgumentException("Callback missing required token value");

        log.debug("Validating IMS Token");

        IMSBearerTokenJwt token = IMSHttpCalls.validateIMSToken(accessToken, moduleOptions);

        //Check if Token has expired
        long now = time.milliseconds();

        log.debug("Token expiration time: {}", token.expirationTime());

        if (now > token.expirationTime()) {
            log.debug("Token has expired! Needs refresh");
            OAuthBearerValidationResult.newFailure("Expired Token").throwExceptionIfFailed();
        }

        //Check if we have DIM specific scope in the token or not
        String scopes = token.scope().toString().replaceAll("[\\[\\]]", "");
        log.debug("Token has following scopes: " + scopes);
        List < String > scopesList = Arrays.asList(scopes.split("\\s*,\\s*"));

        boolean scopeCheckPass = false;
        for (String scope: ALLOWED_SCOPES) {
            if (scopesList.contains(scope)) {
                log.debug("Found valid scope: {}", scope);
                scopeCheckPass = true;
            }
        }

        if (!scopeCheckPass) {
            log.debug("Token doesn't have any of required scopes! We cannot accept this token");
            log.debug("Required scopes are one of the following: {}", Arrays.toString(ALLOWED_SCOPES));
            OAuthBearerValidationResult.newFailure("Required scope missing").throwExceptionIfFailed();
        }

        log.debug("Validated IMS Token: {}", token.toString());
        callback.token(token);
    }
}
