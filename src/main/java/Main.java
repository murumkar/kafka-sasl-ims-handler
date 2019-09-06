package com.adobe.ids.dim.security;

public class Main {

    public static void main(String[] args) {
        IMSBearerTokenJwt token = IMSHttpCalls.getIMSToken();
        String returnedAccessToken = token.value();
        //System.out.println("IMSLoginToken: " + token);
        //System.out.println("Access Token: " + returnedAccessToken);
        token = IMSHttpCalls.validateIMSToken(returnedAccessToken);
        //System.out.println("Token After Validation : " + token);
    }
}