# Java JWT

[![Build Status](https://travis-ci.org/auth0/java-jwt.svg?branch=master)](https://travis-ci.org/auth0/java-jwt)
[![License](http://img.shields.io/:license-mit-blue.svg?style=flat)](http://doge.mit-license.org)

An implementation of [JSON Web Tokens](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html) developed against `draft-ietf-oauth-json-web-token-08` forked from auth0.

## Installation

### Gradle

```gradle
compile 'de.notizwerk:java-jwt:3.0.0'
```

### Maven

```xml
<dependency>
    <groupId>de.notizwerk</groupId>
    <artifactId>java-jwt</artifactId>
    <version>3.0.0</version>
</dependency>
```

## Usage

### Sign JWT (HS256)

```java
final String issuer = "https://mydomain.com/";
final String secret = "{{a secret used for signing}}";

final long iat = System.currentTimeMillis() / 1000l; // issued at claim 
final long exp = iat + 60L; // expires claim. In this case the token expires in 60 seconds

final JWTSigner signer = new JWTSigner(secret);
final HashMap<String, Object> claims = new HashMap<String, Object>();
claims.put("iss", issuer);
claims.put("exp", exp);
claims.put("iat", iat);

final String jwt = signer.sign(claims);
```

### Verify JWT (HS256)

```java
final String secret = "{{secret used for signing}}";
try {
    final JWTVerifier verifier = new JWTVerifier(secret);
    final Map<String,Object> claims= jwtVerifier.verify(jwt);
} catch (JWTVerifyException e) {
    // Invalid Token
}
```

### Validate aud & iss claims

```java
final String secret = "{{secret used for signing}}";
try {
    final JWTVerifier verifier = new JWTVerifier(secret, "{{my-audience}}", "{{my-issuer}}");
    final Map<String,Object> claims= jwtVerifier.verify(jwt);
} catch (JWTVerifyException e) {
    // Invalid Token
}
```


### Why a new fork of another JSON Web Token implementation for Java?

This project is a fork of the [Java JWT project of auth0](https://github.com/auth0/java-jwt).
They believe existing JWT implementations in Java are either too complex or not tested enough. There library aims to be simple and achieve the right level of abstraction. 

In our opinion they reached there goal with their implementation. The only difference between the original library and this fork is the use of faster JSON and base64 codecs. 
For JSON coding we replaced jackson with boon and the apache base64 codec with the jdk base64 codecs. 

... and our favorite build tool is gradle :-)

### performance benchmark

To compare the performance between the auth0 and this implementation start the benchmark. To start the benchmark checkout the benchmark branch and execute 

```
./gradlew jmh
```

To test the compability between this fork and the original fork start 
```
./gradlew compatibilityTest
```

Note: The benchmark and the compability test was made at the time the project was forked.

## Author

[Notizwerk](notizwerk.de)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE.txt) file for more info.
