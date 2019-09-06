package com.adobe.ids.dim.security;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.kafka.common.utils.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.HashMap;
import java.util.Base64;

public class IMSHttpCalls {

    private static final Logger log = LoggerFactory.getLogger(IMSHttpCalls.class);

    // These environment variables should be set on the client side
    private static final String IMS_TOKEN_VALIDATION_URL = (String) getEnvironmentVariables("IMS_TOKEN_VALIDATION_URL", "");
    private static final String IMS_TOKEN_URL = (String) getEnvironmentVariables("IMS_TOKEN_URL", "");
    private static final String IMS_GRANT_TYPE = (String) getEnvironmentVariables("IMS_GRANT_TYPE", "");
    private static final String IMS_CLIENT_ID = (String) getEnvironmentVariables("IMS_CLIENT_ID", "");
    private static final String IMS_CLIENT_SECRET = (String) getEnvironmentVariables("IMS_CLIENT_SECRET", "");
    private static final String IMS_CLIENT_CODE = (String) getEnvironmentVariables("IMS_CLIENT_CODE", "");

    private static Time time = Time.SYSTEM;

    public static IMSBearerTokenJwt getIMSToken() {
        IMSBearerTokenJwt result = null;
        try {
            long callTimeMs = time.milliseconds();

            //POST data
            String grantType = "grant_type=" + IMS_GRANT_TYPE;
            String clientID = "client_id=" + IMS_CLIENT_ID;
            String clientSecret = "client_secret=" + IMS_CLIENT_SECRET;
            String clientCode = "code=" + IMS_CLIENT_CODE;
            String postDataStr = grantType + "&" + clientID + "&" + clientSecret + "&" + clientCode;

            log.debug("Trying to login with IMS");
            log.debug("Request URL: " + IMS_TOKEN_URL + "?" + postDataStr);

            Map<String, Object> resp = null;

            resp = postRequest(IMS_TOKEN_URL , postDataStr);


            //for (Map.Entry entry : resp.entrySet()) {
                //log.debug("key: " + entry.getKey() + "; value: " + entry.getValue());
            //}


            if(resp != null){

                String accessToken = (String) resp.get("access_token");
                long expiresInMs = ((Integer) resp.get("expires_in")).longValue();

                log.debug("Got AccessToken: " + accessToken);

                try {
                    result = new IMSBearerTokenJwt(accessToken, expiresInMs, callTimeMs);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else {
                throw new Exception("Response NULL at getIMSToken");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static IMSBearerTokenJwt validateIMSToken(String accessToken) {

        IMSBearerTokenJwt result = null;

        try {

            // Get client_id from access token
            String clientID = "client_id=" + getClientIdFromJWT(accessToken);

            // Other parameters needed for the POST call
            String token = "token=" + accessToken;
            String type = "type=access_token";

            String postDataStr = token + "&" + clientID + "&" + type;

            log.debug("Trying to validate token with IMS");
            log.debug("Request URL: " + IMS_TOKEN_VALIDATION_URL + "?" + postDataStr);

            Map<String, Object> resp = null;
            Map<String, Object> tokenJson = null;

            resp = postRequest(IMS_TOKEN_VALIDATION_URL, postDataStr);

            //for (Map.Entry entry : resp.entrySet()) {
                //log.debug("key: " + entry.getKey() + "; value: " + entry.getValue());
            //}

            if (resp != null) {
                if ((boolean) resp.get("valid")) {

                    log.debug("Token is Valid!");

                    // Extract the token and convert it to a Map<String, Object>
                    ObjectMapper oMapper = new ObjectMapper();
                    tokenJson = oMapper.convertValue(resp.get("token"), Map.class);

                    result = new IMSBearerTokenJwt(tokenJson, accessToken);

                } else {
                    throw new Exception("Expired Token");
                }
            }

        } catch(Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static String getClientIdFromJWT(String accessToken) {

        String clientID = null;
        // Get client_id from the token
        String[] tokenString = accessToken.split("\\.");
        Base64.Decoder decoder = Base64.getUrlDecoder();

        String payLoad = new String(decoder.decode(tokenString[1]));

        Map<String, String> bodyItems = new HashMap<String, String>();
        String[] pairs = payLoad.split("\",\"");

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> payloadJson = objectMapper.readValue(payLoad, new TypeReference<Map<String,Object>>(){});
            clientID = (String) payloadJson.get("client_id");
        } catch (IOException e){
            e.printStackTrace();
            return null;
        }

        return clientID;
    }


    private static Map<String, Object> postRequest(String urlStr, String postParameters){
        try{

            byte[] postData = postParameters.getBytes( StandardCharsets.UTF_8 );
            int postDataLength = postData.length;

            URL url = new URL(urlStr);
            HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
            con.setInstanceFollowRedirects(true);
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            con.setRequestProperty("charset", "utf-8");
            con.setRequestProperty("Content-Length", Integer.toString(postDataLength));
            con.setUseCaches(false);
            con.setDoOutput(true);

            try(DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
                wr.write( postData );
            }

            int responseCode = con.getResponseCode();
            if (responseCode == 200) {
                return handleJsonResponse(con.getInputStream());
            }else {
                throw new Exception("Return code " + responseCode);
            }
        }catch (Exception e){
            log.error("at postRequest");
        }
        return null;
    }

    private static Object getEnvironmentVariables(String envName, Object defaultValue) {
        Object result = null;
        String env = System.getenv(envName);
        if(env == null){
            result = defaultValue;
        }else{
            if(defaultValue instanceof Boolean){
                result = Boolean.valueOf(env);
            }else if(defaultValue instanceof Integer){
                result = Integer.valueOf(env);
            }else if(defaultValue instanceof Double){
                result = Double.valueOf(env);
            }else if(defaultValue instanceof Float){
                result = Float.valueOf(env);
            }else{
                result = env;
            }
        }
        return result;
    }

    private static Map<String,Object> handleJsonResponse(InputStream inputStream){
        Map<String, Object> result = null;
        try{
            BufferedReader in = new BufferedReader(new InputStreamReader(inputStream));
            String inputLine;
            StringBuffer response = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();

            String jsonResponse = response.toString();
            ObjectMapper objectMapper = new ObjectMapper();
            result = objectMapper.readValue(jsonResponse, new TypeReference<Map<String,Object>>(){});

        }catch (Exception e){
            e.printStackTrace();
        }
        return result;
    }

}