/*
 * ADOBE CONFIDENTIAL. Copyright 2018 Adobe Systems Incorporated. All Rights Reserved. NOTICE: All information contained
 * herein is, and remains the property of Adobe Systems Incorporated and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Adobe Systems Incorporated and its suppliers and are protected
 * by all applicable intellectual property laws, including trade secret and copyright law. Dissemination of this
 * information or reproduction of this material is strictly forbidden unless prior written permission is obtained
 * from Adobe Systems Incorporated.
 */

package com.manoj.security;

import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IMSBearerTokenJwt implements OAuthBearerToken {

    private final Logger log = LoggerFactory.getLogger(IMSBearerTokenJwt.class);

    private String value;
    private String principalName;
    private Long startTimeMs;
    private long lifetimeMs;
    private Set<String> scope;
    private Long expirationTime;


    public IMSBearerTokenJwt(String accessToken, long lifeTime, long startTime){
        super();
        this.value = accessToken;
        this.principalName = null;
        this.startTimeMs = startTime;
        this.lifetimeMs = startTimeMs + lifeTime;
        this.expirationTime = lifetimeMs;
    }

    public IMSBearerTokenJwt(Map<String, Object> jwtToken, String accessToken){
        super();
        this.value = accessToken;
        this.principalName = (String) jwtToken.get("user_id");

        //for (Map.Entry entry : jwtToken.entrySet()) {
            //log.debug("jwtToken key: " + entry.getKey() + "; jwtToken value: " + entry.getValue());
        //}

        if(this.scope == null){
            this.scope = new TreeSet<>();
        }

        if(jwtToken.get("scope") instanceof String ){
            this.scope.add((String) jwtToken.get("scope"));
        }else if(jwtToken.get("scope") instanceof List){
            for(String s : (List<String>) jwtToken.get("scope")){
                this.scope.add(s);
            }
        }

        long expiresInMs = Long.parseLong((String) jwtToken.get("expires_in"));
        long creationTimeMs = Long.parseLong((String) jwtToken.get("created_at"));

        this.startTimeMs = creationTimeMs;
        this.lifetimeMs = expiresInMs;
        this.expirationTime = creationTimeMs + expiresInMs;

    }

    @Override
    public String value() {
        return value;
    }

    @Override
    public Set<String> scope() {
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

    public long expirationTime() {  return expirationTime != null ? expirationTime : 0; }

   /** @Override
    public String toString() {
        return "IMSBearerTokenJwt{" +
                "value='" + value + '\'' +
                ", lifetimeMs=" + lifetimeMs +
                ", principalName='" + principalName + '\'' +
                ", startTimeMs=" + startTimeMs +
                ", scope=" + scope +
                ", expirationTime=" + expirationTime +
                '}';
    }
   */

}