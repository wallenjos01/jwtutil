# JWTUtil
*A library and command line utility for generating, parsing, and validating [JSON Web Tokens](https://www.rfc-editor.org/info/rfc7519) (JWTs)*


## CLI Usage

First, download the latest build from the [Releases](https://github.com/wallenjos01/jwtutil/releases) page. It 
requires Java 21 or newer. <br/>
Run it using a command like the following: `java -jar jwtutil.jar <mode> <key> <data>`
- `<mode>` is either `encode` or `decode`
- `<key>` is the path to the key file to use.
- `<data>` is JSON payload data if the mode is `encode`, or an existing JWT if the mode is `decode`

### Key files
Key files should have one of the following extensions:
- `.key`: HMAC key used for signing or validating unencrypted JWTs (See [JSON Web Signature](https://www.rfc-editor.org/info/rfc7515))
- `.aes`: AES key used for encrypting or decrypting symmetric encrypted JWTs (See [JSON Web Encryption](https://www.rfc-editor.org/info/rfc7516))
- `.pub`: An RSA public key used for encrypting asymmetric encrypted JWTs
- `.rsa`: An RSA private key used for decrypting asymmetric encrypted JWTs

## Library Usage

### Installation
The library is published in the maven repository at `https://maven.wallentines.org/releases`.
The latest version is `0.1.0`.

### Creating a JWT
Creating a JWT is done using the `JWTBuilder` class. Simply specify the claims and security method using the provided
methods. 

Example 1: Creating an unencrypted, signed JWT.
```java
byte[] keyBytes = [...];
String token = new JWTBuilder()
                .issuedNow()
                .issuedBy("MyWebService")
                .expiresIn(86400) // Seconds in a day
                .withClaim("usr", "Username")
                [...]
                .signed(HashCodec.HS512(keyBytes))
                .asString().getOrThrow();
```

Example 2: Creating a JWT encrypted with AES256 for both the key and content encryption.
```java
byte[] keyBytes = [...];
String token = new JWTBuilder()
                .issuedNow()
                .issuedBy("MyWebService")
                .expiresIn(86400) // Seconds in a day
                .withClaim("usr", "Username")
                [...]
                .encrypted(KeyCodec.A256KW(keyBytes), CryptCodec.A256CBC_HS512())
                .asString().getOrThrow();
```

### Parsing a JWT
Parsing a JWT is done using the `JWTReader` class. Simply call the `readAny` static method with the JWT and a `KeySupplier`
object. The reader will read the JOSE header to determine which key is required and ask the provided `KeySupplier` for 
it. The simplest `KeySupplier` is one that only contains a single key, but more complex `KeySupplier` implementations 
can be created in situations where more than one key can be valid.

Example 3: Parsing an unencrypted, signed JWT
```java
String token = [...];
byte[] keyBytes = [...];
KeySupplier supplier = KeySupplier.of(HashCodec.HS512(keyBytes));
SerializeResult<JWT> parseResult = JWTReader.readAny(token, supplier);

if(parseResult.isSuccess()) {
    JWT token = parseResult.getOrThrow();
} else {
    // Handle failed parse. (Invalid JWT or invalid key)
}

```

Example 4: Parsing a JWT encrypted with AES256 key encryption.
```java
String token = [...];
byte[] keyBytes = [...];
KeySupplier supplier = KeySupplier.of(KeyCodec.A256KW(keyBytes));
SerializeResult<JWT> parseResult = JWTReader.readAny(token, supplier);

if(parseResult.isSuccess()) {
    JWT token = parseResult.getOrThrow();
} else {
    // Handle failed parse. (Invalid JWT or invalid key)
}
```


### Validating a JWT
Validating a JWT is done using the `JWTVerifier` class. A simple `JWTVerifier` simply checks if the JWT is expired, but
they can be configured as you like to require specific claims, require unique claims, require encryption, and more.

Example 5: Verifying a JWT is valid
```java
JWT token = [...];
JWTVerifier verifier = new JWTVerifier();
boolean valid = verifier.verify(token);
```

Example 6: Verifying a JWT is valid, encrypted, issued by a specific service, and has a valid `usr` claim. (According to 
some domain-specific `userCache` object)
```java
JWT token = [...];
JWTVerifier verifier = new JWTVerifier()
        .requireEncrypted()
        .withClaim("iss", "MyWebService")
        .withClaim("usr", obj -> obj.isString() && userCache.hasUser(obj.asString()));
boolean valid = verifier.verify(token);
```


### KeyStores
A `KeyStore` is, as the name would suggest, storage for keys. As an interface it declares methods for retrieving, putting,
or clearing keys by name. By default, one implementation exists: the `FileKeyStore`, which stores keys on disk. From 
a `KeyStore` you can create `KeySupplier` objects. 

Example 7: Using a FileKeyStore to encode and decode tokens.
```java
KeyStore keyStore = new FileKeyStore(Path.of("keys")); // Assume the file "keys/example.aes" exists
JWTVerifier verifier = new JWTVerifier()
        .requireEncrypted()
        .withClaim("iss", "MyWebService");

String generateToken(ConfigSection payload) {
    
    return JWTBuilder()
            .issuedNow()
            .issuedBy("MyWebService")
            .expiresIn(86400) // Seconds in a day
            .withClaim("usr", "Username")
            .build(KeyType.AES, "example", keyStore) // Will put "example" into the "kid" header claim of the token
            .asString().getOrThrow();
}

boolean parseAndVerify(String token) {
    
    KeySupplier keySupplier = keyStore.supplier(); // Will search for the key specified by the "kid" header claim of the token.
    SerializeResult<JWT> out = JWTReader.readAny(token, keySupplier); 
    if(!out.isSuccess()) return false;
    
    return verifier.verify(out.getOrThrow());
}
```