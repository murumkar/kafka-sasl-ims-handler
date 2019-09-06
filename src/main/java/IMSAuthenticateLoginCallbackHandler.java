/**
 *
 * https://docs.confluent.io/current/kafka/authentication_sasl/authentication_sasl_oauth.html
 *
 * Login Callback Handler for Token Retrieval
 * You must provide an implementation of org.apache.kafka.common.security.auth.AuthenticateCallbackHandler that handles
 * an instance of org.apache.kafka.common.security.oauthbearer.OAuthBearerTokenCallback. You can declare it using either
 * the sasl.login.callback.handler.class configuration option for a non-broker client, or using the prefixed
 * listener.name.sasl_ssl.oauthbearer.sasl.login.callback.handler.class configuration option for brokers (when SASL/OAUTHBEARER is
 * the inter-broker protocol).
 */


package com.adobe.ids.dim.security;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerTokenCallback;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import java.io.IOException;
import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IMSAuthenticateLoginCallbackHandler implements AuthenticateCallbackHandler {
    private final Logger log = LoggerFactory.getLogger(IMSAuthenticateLoginCallbackHandler.class);
    private Map<String, String> moduleOptions = null;
    private boolean configured = false;

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

    public boolean isConfigured(){
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
            if (callback instanceof OAuthBearerTokenCallback)
                try {
                    handleCallback((OAuthBearerTokenCallback) callback);
                } catch (KafkaException e) {
                    throw new IOException(e.getMessage(), e);
                }
            else
                throw new UnsupportedCallbackException(callback);
        }
    }

    private void handleCallback(OAuthBearerTokenCallback callback){
        if (callback.token() != null)
            throw new IllegalArgumentException("Callback had a token already");

        log.debug("Trying to acquire IMS Token");

        IMSBearerTokenJwt token = IMSHttpCalls.getIMSToken();

        if(token == null){
            throw new IllegalArgumentException("Null token returned from server");
        }

        log.debug("Retrieved IMS Token");
        callback.token(token);
    }

}
