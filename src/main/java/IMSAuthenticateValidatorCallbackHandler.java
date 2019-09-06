/**
 *
 * https://docs.confluent.io/current/kafka/authentication_sasl/authentication_sasl_oauth.html
 *
 * Server Callback Handler for Token Validation
 * You must provide an implementation of org.apache.kafka.common.security.auth.AuthenticateCallbackHandler
 * that handles an instance of org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallback.
 * You can declare it using the prefixed listener.name.sasl_ssl.oauthbearer.sasl.server.callback.handler.class
 * broker configuration option.
 */

package com.adobe.ids.dim.security;

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

public class IMSAuthenticateValidatorCallbackHandler implements AuthenticateCallbackHandler {
    private final Logger log = LoggerFactory.getLogger(IMSAuthenticateValidatorCallbackHandler.class);
    private List<AppConfigurationEntry> jaasConfigEntries;
    private Map<String, String> moduleOptions = null;
    private boolean configured = false;
    private Time time = Time.SYSTEM;

    @Override
    public void configure(Map<String, ?> map, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        if (!OAuthBearerLoginModule.OAUTHBEARER_MECHANISM.equals(saslMechanism))
            throw new IllegalArgumentException(String.format("Unexpected SASL mechanism: %s", saslMechanism));
        if (Objects.requireNonNull(jaasConfigEntries).size() != 1 || jaasConfigEntries.get(0) == null)
            throw new IllegalArgumentException(
                    String.format("Must supply exactly 1 non-null JAAS mechanism configuration (size was %d)",
                            jaasConfigEntries.size()));
        this.moduleOptions = Collections.unmodifiableMap((Map<String, String>) jaasConfigEntries.get(0).getOptions());
        configured = true;
    }

    public boolean isConfigured() {
        return this.configured;
    }

    @Override
    public void close() {
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (!isConfigured())
            throw new IllegalStateException("Callback handler not configured");
        for (Callback callback : callbacks) {
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

    private void handleCallback(OAuthBearerValidatorCallback callback) {
        String accessToken = callback.tokenValue();
        if (accessToken == null)
            throw new IllegalArgumentException("Callback missing required token value");

        log.debug("Validating IMS Token");
        IMSBearerTokenJwt token = IMSHttpCalls.validateIMSToken(accessToken);

        //Check if Token has expired
        long now = time.milliseconds();
        if (now > token.expirationTime()) {
            OAuthBearerValidationResult.newFailure("Expired Token, needs refresh!");
        }

        log.debug("Validated IMS Token");
        callback.token(token);
    }
}