package com.manoj.security;

import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IMSBearerTokenJwt implements OAuthBearerToken {

    private final Logger log = LoggerFactory.getLogger(IMSBearerTokenJwt.class);

    private String value;
    private String principalName;
    private Long startTimeMs;
    private long lifetimeMs;
    private Set < String > scope;

    public IMSBearerTokenJwt(String accessToken, long lifeTime, long startTime) {
        super();
        this.value = accessToken;
        this.principalName = null;
        this.startTimeMs = startTime;
        this.lifetimeMs = startTimeMs + lifeTime;
    }

    public IMSBearerTokenJwt(Map < String, Object > jwtToken, String accessToken) {
        super();
        this.value = accessToken;
        this.principalName = (String) jwtToken.get("client_id");

        if (this.scope == null) {
            this.scope = new TreeSet < > ();
        }

        if (jwtToken.get("scope") instanceof String) {
            //IMS scopes come in the form of a comma separated string
            List<String> scopesList = Arrays.asList(jwtToken.get("scope").toString().split("\\s*,\\s*"));
            for (String s: (List < String > ) scopesList) {
                this.scope.add(s);
            }
        } else if (jwtToken.get("scope") instanceof List) {
            for (String s: (List < String > ) jwtToken.get("scope")) {
                this.scope.add(s);
            }
        }

        long expiresInMs = Long.parseLong((String) jwtToken.get("expires_in"));
        long creationTimeMs = Long.parseLong((String) jwtToken.get("created_at"));

        this.startTimeMs = creationTimeMs;
        this.lifetimeMs = creationTimeMs + expiresInMs;
    }

    @Override
    public String value() {
        return value;
    }

    @Override
    public Set < String > scope() {
        return scope;
    }

    @Override
    public long lifetimeMs() {
        return lifetimeMs;
    }

    @Override
    public String principalName() {
        return principalName;
    }

    @Override
    public Long startTimeMs() {
        return startTimeMs != null ? startTimeMs : 0;
    }

    @Override
    public String toString() {
        return "IMSBearerTokenJwt{" +
                "value='" + value + '\'' +
                ", lifetimeMs=" + lifetimeMs +
                ", principalName='" + principalName + '\'' +
                ", startTimeMs=" + startTimeMs +
                ", scope=" + scope() +
                '}';
    }

}
