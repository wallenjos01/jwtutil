package org.wallentines.jwt;

import org.wallentines.mdcfg.ConfigObject;
import org.wallentines.mdcfg.ConfigSection;
import org.wallentines.mdcfg.serializer.SerializeResult;
import org.wallentines.mdcfg.serializer.Serializer;

import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

public class JWTBuilder {

    private final ConfigSection payload = new ConfigSection();
    private final Clock clock = Clock.systemUTC();

    public JWTBuilder withClaim(String claim, String value) {
        payload.set(claim, value);
        return this;
    }
    public JWTBuilder withClaim(String claim, Boolean value) {
        payload.set(claim, value);
        return this;
    }
    public JWTBuilder withClaim(String claim, Number value) {
        payload.set(claim, value);
        return this;
    }

    public <T> JWTBuilder withClaim(String claim, T value, Serializer<T> serializer) {
        payload.set(claim, value, serializer);
        return this;
    }

    public JWTBuilder withClaims(ConfigSection payload) {

        for(String key : payload.getKeys()) {
            ConfigObject obj = payload.get(key);
            if(!obj.isPrimitive()) continue;

            if(obj.isString()) {
                withClaim(key, obj.asString());
            }
            if(obj.isBoolean()) {
                withClaim(key, obj.asBoolean());
            }
            if(obj.isNumber()) {
                withClaim(key, obj.asNumber());
            }
        }

        return this;
    }

    public JWTBuilder issuedBy(String issuer) {
        return withClaim("iss", issuer);
    }

    public JWTBuilder issuedNow() {
        return issuedAt(clock.instant().truncatedTo(ChronoUnit.SECONDS));
    }

    public JWTBuilder issuedAt(Instant instant) {
        return withClaim("iat", instant.getEpochSecond());
    }

    public JWTBuilder expiresIn(long seconds) {
        return expiresAt(clock.instant().truncatedTo(ChronoUnit.SECONDS).plusSeconds(seconds));
    }

    public JWTBuilder expiresAt(Instant instant) {
        return withClaim("exp", instant.getEpochSecond());
    }

    public JWTBuilder validIn(long seconds) {
        return validAt(clock.instant().truncatedTo(ChronoUnit.SECONDS).plusSeconds(seconds));
    }

    public JWTBuilder validAt(Instant instant) {
        return withClaim("nbf", instant.getEpochSecond());
    }

    public JWSSerializer.JWS signed(HashCodec<?> codec, String keyId) {

        ConfigSection header = new ConfigSection();
        if(keyId != null) header.set("kid", keyId);
        header.set("typ", "JWT");

        return new JWSSerializer.JWS(codec, header, payload);
    }

    public JWSSerializer.JWS signed(HashCodec<?> codec) {
        return signed(codec, null);
    }


    public JWSSerializer.JWS unsecured() {
        return signed(HashCodec.none());
    }


    public JWESerializer.JWE encrypted(KeyCodec<?,?> keyCodec, CryptCodec<?> contentCodec) {

        return encrypted(keyCodec, contentCodec, null);
    }

    public JWESerializer.JWE encrypted(KeyCodec<?,?> keyCodec, CryptCodec<?> contentCodec, String keyId) {

        ConfigSection header = new ConfigSection();
        if(keyId != null) header.set("kid", keyId);
        header.set("typ", "JWT");

        return new JWESerializer.JWE(keyCodec, contentCodec, header, payload);
    }


    public <T> SerializeResult<JWT> build(KeyType<T> kt, String keyId, T key) {
        if(kt == KeyType.HMAC) {
            return SerializeResult.success(signed(KeyType.HMAC.createHashCodec((byte[]) key), keyId));
        }
        if(kt == KeyType.AES) {
            return SerializeResult.success(encrypted(KeyType.AES.createKeyCodec((SecretKey) key), CryptCodec.A256CBC_HS512(), keyId));
        }
        if(kt == KeyType.RSA_PUBLIC) {
            return SerializeResult.success(encrypted(KeyType.RSA_PUBLIC.createKeyCodec((PublicKey) key), CryptCodec.A256CBC_HS512(), keyId));
        }
        return SerializeResult.failure("Unsupported key type!");
    }

    public <T> SerializeResult<JWT> build(KeyType<T> kt, T key) {
        return build(kt, null, key);
    }

    public <T> SerializeResult<JWT> build(KeyType<T> kt, byte[] encodedKey) {
        return kt.create(encodedKey).map(key -> build(kt, key));
    }

    public <T> SerializeResult<JWT> build(KeyType<T> kt, String keyId, KeyStore keyStore) {
        T key = keyStore.getKey(keyId, kt);
        if(key == null) {
            return SerializeResult.failure("Key not found!");
        }
        return build(kt, key);
    }

}
