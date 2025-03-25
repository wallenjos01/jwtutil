package org.wallentines.jwt.util;

import org.wallentines.jwt.*;
import org.wallentines.mdcfg.codec.JSONCodec;
import org.wallentines.mdcfg.serializer.ConfigContext;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class Main {

    public static void main(String[] args) {

        if(args.length != 3) {
            System.out.println("Usage: jwtutil <mode> <key> <data>");
        }

        String mode = args[0];
        Path keyFile = Path.of(args[1]);
        KeyType<?> kt = KeyType.forFile(keyFile);

        byte[] rawKey;
        try {
            rawKey = Files.readAllBytes(keyFile);
        } catch (IOException ex) {
            throw new RuntimeException("Failed to read key file", ex);
        }

        switch (mode) {
            case "decode":
            case "d": {
                decode(args[2], rawKey, kt);
                break;
            }
            case "encode":
            case "e": {
                encode(args[2], rawKey, kt);
                break;
            }
            default: {
                System.out.println("Unknown mode: " + mode);
            }
        }

    }


    private static void decode(String tokenStr, byte[] keyData, KeyType<?> kt) {
        System.out.println(JSONCodec.readable()
                .encodeToString(
                        ConfigContext.INSTANCE,
                        JWTReader.readAny(tokenStr, KeySupplier.read(keyData, kt)
                                .getOrThrow()
                        ).getOrThrow().payload()
                )
        );
    }

    private static void encode(String payload, byte[] keyData, KeyType<?> kt) {

        System.out.println(new JWTBuilder()
                .withClaims(JSONCodec.loadConfig(payload).asSection())
                .build(kt, keyData)
                .getOrThrow()
                .asString()
                .getOrThrow());
    }

}
