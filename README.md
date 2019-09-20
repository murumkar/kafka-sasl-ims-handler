# kafka-sasl-ims-handler
This is an implementation of the idea that was circulated as part of [KIP-255](https://cwiki.apache.org/confluence/pages/viewpage.action?pageId=75968876) that makes it possible to use [IMS](https://wiki.corp.adobe.com/pages/viewpage.action?spaceKey=ims&title=IMS+Home) to authenticate Java clients against Kafka clusters.

## Configure brokers
* Add skinny jar that is created after building the module (kafka-sasl-ims-handler-1.0-SNAPSHOT.jar, for example) to kafka lib directory (/usr/share/java/kafka).
* Start the brokers with following JAAS configuration. IMS token validation URL depends on the environment.

```
KafkaServer {
    org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required
    ims.token.validation.url="<URL>"
    LoginStringClaim_sub="admin";
};
```
* In addition, brokers need following properties set.

| Property | Value |
| :-------:|:-----:|
| listener.name.sasl_plaintext.oauthbearer.sasl.server.callback.handler.class | com.adobe.ids.dim.security.IMSAuthenticateValidatorCallbackHandler |
| sasl.enabled.mechanisms | OAUTHBEARER |


## Configure clients
* Add fat jar that is created after building the module (kafka-sasl-ims-handler-1.0-SNAPSHOT-jar-with-dependencies.jar, for example) to the classpath of the client.
* Java clients need to set following properties in the code (or via settings).

| Property | Value |
| :-------:|:-----:|
| security.protocol | SASL_PLAINTEXT |
| sasl.mechanism  | OAUTHBEARER |
| sasl.login.callback.handler.class | com.adobe.ids.dim.security.IMSAuthenticateLoginCallbackHandler |


* In addition, clients need to be started with following JAAS configuration. IMS token  URL depends on the environment. Client ID, client secret and client code are issued to each client when they register with IMS and are unique to each client.

```
KafkaClient {
    org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required
    ims.token.url="<URL>"
    ims.grant.type="authorization_code" 
    ims.client.id="<Client ID>"
    ims.client.secret="<Client Secret>"
    ims.client.code="<Client Code>";
};
```
