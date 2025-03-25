package org.wallentines.jwt;

import org.jetbrains.annotations.Nullable;
import org.wallentines.mdcfg.serializer.SerializeResult;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public interface KeyType<T> {

    SerializeResult<T> create(byte[] bytes);

    SerializeResult<byte[]> serialize(T key);

    RsaPrivate RSA_PRIVATE = new RsaPrivate();
    RsaPublic RSA_PUBLIC = new RsaPublic();
    Secret AES = new Secret("AES");
    Hmac HMAC = new Hmac();


    @Nullable
    static KeyType<?> forFile(Path keyFile) {
        String fileName = keyFile.getFileName().toString();
        return forFile(fileName);
    }

    @Nullable
    static KeyType<?> forFile(String fileName) {
        String ext = fileName.substring(fileName.lastIndexOf('.') + 1);
        return forExtension(ext);
    }

    @Nullable
    static KeyType<?> forExtension(String ext) {
        return switch (ext) {
            case "key" -> KeyType.HMAC;
            case "aes" -> KeyType.AES;
            case "pub" -> KeyType.RSA_PUBLIC;
            case "rsa" -> KeyType.RSA_PRIVATE;
            default -> null;
        };
    }


    class RsaPrivate implements KeyType<PrivateKey> {
        @Override
        public SerializeResult<PrivateKey> create(byte[] bytes) {
            try {
                return SerializeResult.success(KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes, "RSA")));
            } catch (GeneralSecurityException ex) {
                return SerializeResult.failure("Unable to read RSA private key!");
            }
        }
        @Override
        public SerializeResult<byte[]> serialize(PrivateKey key) {
            if(key.getAlgorithm().equals("RSA")) {
                return SerializeResult.success(key.getEncoded());
            }
            return SerializeResult.failure("Expected an RSA Key!");
        }

        public KeyCodec<PublicKey, PrivateKey> createKeyCodec(PrivateKey key) {
            return KeyCodec.RSA_OAEP(key);
        }
    };


    class RsaPublic implements KeyType<PublicKey> {
        @Override
        public SerializeResult<PublicKey> create(byte[] bytes) {
            try {
                return SerializeResult.success(KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes, "RSA")));
            } catch (GeneralSecurityException ex) {
                return SerializeResult.failure("Unable to read RSA private key!");
            }
        }
        @Override
        public SerializeResult<byte[]> serialize(PublicKey key) {
            if(key.getAlgorithm().equals("RSA")) {
                return SerializeResult.success(key.getEncoded());
            }
            return SerializeResult.failure("Expected an RSA Key!");
        }

        public KeyCodec<PublicKey, PrivateKey> createKeyCodec(PublicKey key) {
            return KeyCodec.RSA_OAEP(key);
        }
    };



    class Hmac implements KeyType<byte[]> {
        @Override
        public SerializeResult<byte[]> create(byte[] bytes) {
            return SerializeResult.success(bytes);
        }
        @Override
        public SerializeResult<byte[]> serialize(byte[] key) {
            return SerializeResult.success(key);
        }

        public HashCodec<byte[]> createHashCodec(byte[] key) {
            return switch (key.length) {
                case 32 -> HashCodec.HS256(key);
                case 48 -> HashCodec.HS384(key);
                case 64 -> HashCodec.HS512(key);
                default -> throw new IllegalArgumentException("Invalid key length!");
            };
        }
    }

    class Secret implements KeyType<SecretKey> {
        private final String algorithm;

        public Secret(String algorithm) {
            this.algorithm = algorithm;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        @Override
        public SerializeResult<SecretKey> create(byte[] bytes) {
            return SerializeResult.success(new SecretKeySpec(bytes, algorithm));
        }
        @Override
        public SerializeResult<byte[]> serialize(SecretKey key) {
            if(key.getAlgorithm().equals(algorithm)) {
                return SerializeResult.success(key.getEncoded());
            }
            return SerializeResult.failure("Expected secret key with algorithm " + key.getAlgorithm());
        }

        public KeyCodec<SecretKey, SecretKey> createKeyCodec(SecretKey key) {
            return switch (key.getEncoded().length) {
                case 16 -> KeyCodec.A128KW(key);
                case 24 -> KeyCodec.A192KW(key);
                case 32 -> KeyCodec.A256KW(key);
                default -> throw new IllegalArgumentException("Invalid key length!");
            };
        }
    }

}
