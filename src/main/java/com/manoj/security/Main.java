/*
 * ADOBE CONFIDENTIAL. Copyright 2018 Adobe Systems Incorporated. All Rights Reserved. NOTICE: All information contained
 * herein is, and remains the property of Adobe Systems Incorporated and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Adobe Systems Incorporated and its suppliers and are protected
 * by all applicable intellectual property laws, including trade secret and copyright law. Dissemination of this
 * information or reproduction of this material is strictly forbidden unless prior written permission is obtained
 * from Adobe Systems Incorporated.
 */

package com.manoj.security;

import java.util.Map;
import java.util.TreeMap;

public class Main {

    public static void main(String[] args) {
        Map<String,String> configOptions = new TreeMap<>();
        configOptions.put("ims.token.validation.url","https://manojid-na1-dev1.services.adobe.com/ims/validate_token/v1");
        configOptions.put("ims.token.url","https://manojid-na1-dev1.services.adobe.com/ims/token/v1");
        configOptions.put("ims.grant.type","authorization_code");
        configOptions.put("ims.client.id","DIM_Internal_Client");
        configOptions.put("ims.client.secret","c175e496-f9e4-4afd-a6fd-cb9ff1710adb");
        configOptions.put("ims.client.code","eyJ4NXUiOiJpbXMta2V5LTEuY2VyIiwiYWxnIjoiUlMyNTYifQ.eyJpZCI6IkRJTV9JbnRlcm5hbF9DbGllbnRfZGV2cWEiLCJjbGllbnRfaWQiOiJESU1fSW50ZXJuYWxfQ2xpZW50IiwidXNlcl9pZCI6IkRJTV9JbnRlcm5hbF9DbGllbnRAQWRvYmVJRCIsInR5cGUiOiJhdXRob3JpemF0aW9uX2NvZGUiLCJhcyI6Imltcy1uYTEtZGV2MSIsIm90byI6ImZhbHNlIiwiZXhwaXJlc19pbiI6IjI1OTIwMDAwMDAwMCIsInNjb3BlIjoic3lzdGVtLEFkb2JlSUQsb3BlbmlkIiwiY3JlYXRlZF9hdCI6IjE1NjcxODYyMDE0MjEifQ.W7Fjua37I272Xdp074jXLZmxHQFS3xYwNGjoV-iZQ1qkKVF46DB3kOGvZNfiHIu-w4uyBCmN9JKVpkiY-9upjS20DEweu9HD-d6tATwv5-A6Z_H_DBjqmI9747bV1LKgdWB3TAMGii0HKgXbsNiCycr5RqTysKlW5Db9C5zOwBuGyanyS4_RdJ1pNhwft0vZ_3AY_km5rGvymGYQSGKKnhpRrExA21D7jBCD1UVuwjKoyyduTtWMwW1eG_HoHGsvdACAX415oPMwiFK1rc8SLFI1AQ-Vw_qUw5hmc26YxIUvFdUEF6Yu00pr1KHGN_Lv7C6p30fkpIQ5IUvZ2u35mg");

        IMSBearerTokenJwt token = IMSHttpCalls.getIMSToken(configOptions);
        String returnedAccessToken = token.value();
        System.out.println("IMSLoginToken: " + token);
        System.out.println("Access Token: " + returnedAccessToken);
        IMSBearerTokenJwt tokenIntrospected = IMSHttpCalls.validateIMSToken(returnedAccessToken, configOptions);
        System.out.println("Token After Validation : " + tokenIntrospected);
    }
}
