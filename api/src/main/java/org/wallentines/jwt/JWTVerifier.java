package org.wallentines.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wallentines.mdcfg.ConfigObject;
import org.wallentines.mdcfg.ConfigPrimitive;

import java.time.Clock;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Predicate;

public class JWTVerifier {

    private static final Logger LOGGER = LoggerFactory.getLogger("JWTVerifier");
    private final Clock clock;
    private final Map<String, Predicate<ConfigObject>> verify;
    private boolean allowExpired;
    private boolean allowUnprotected;
    private boolean requireEncrypted;
    private UsedTokenCache oneTimeCache;

    public JWTVerifier() {
        this.clock = Clock.systemUTC();
        this.verify = new HashMap<>();
    }

    public JWTVerifier withClaim(String claim, String value) {
        verify.put(claim, obj -> obj.isString() && obj.asString().equals(value));
        return this;
    }

    public JWTVerifier withClaim(String claim, Number value) {
        verify.put(claim, obj -> obj.isNumber() && obj.asNumber().equals(value));
        return this;
    }

    public JWTVerifier withClaim(String claim, Boolean value) {
        verify.put(claim, obj -> obj.isBoolean() && obj.asBoolean().equals(value));
        return this;
    }

    public JWTVerifier withClaim(String claim, ConfigObject value) {
        verify.put(claim, obj -> obj.equals(value));
        return this;
    }

    public JWTVerifier withClaim(String claim, Predicate<ConfigObject> predicate) {
        verify.put(claim, predicate);
        return this;
    }

    public JWTVerifier allowExpired() {
        this.allowExpired = true;
        return this;
    }

    public JWTVerifier allowUnprotected() {
        this.allowUnprotected = true;
        return this;
    }

    public JWTVerifier requireEncrypted() {
        this.requireEncrypted = true;
        return this;
    }

    public JWTVerifier enforceSingleUse(UsedTokenCache cache) {
        this.oneTimeCache = cache;
        return this;
    }

    public boolean verify(JWT jwt) {

        if(!allowExpired && (jwt.isExpired(clock) || !jwt.isValid(clock))) {
            return false;
        }

        if(!allowUnprotected && jwt.isUnprotected()) {
            return false;
        }

        if(requireEncrypted && !jwt.isEncrypted()) {
            return false;
        }

        if(oneTimeCache != null && !oneTimeCache.validate(jwt)) {
            LOGGER.warn("Found reused one-time token! {}", oneTimeCache.getIdClaim());
            return false;
        }

        for(Map.Entry<String, Predicate<ConfigObject>> ent : verify.entrySet()) {
            ConfigObject obj = jwt.getClaim(ent.getKey());
            if(obj == null || !ent.getValue().test(obj)) {
                return false;
            }
        }
        return true;
    }

}
