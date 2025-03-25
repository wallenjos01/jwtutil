import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.wallentines.jwt.HashCodec;
import org.wallentines.jwt.JWSSerializer;
import org.wallentines.jwt.JWT;
import org.wallentines.jwt.JWTBuilder;

public class TestExpiration {

    @Test
    public void testExpired() {

        String secret = "MY_SECRET_KEY";
        HashCodec<?> codec = HashCodec.HS256(secret.getBytes());

        JWSSerializer.JWS jws = new JWTBuilder()
                .expiresIn(-1)
                .signed(codec);

        String ser = jws.asString().getOrThrow();

        JWT parsed = JWSSerializer.read(ser, codec).getOrThrow();
        Assertions.assertTrue(parsed.isExpired());
    }

    @Test
    public void testNotExpired() {

        String secret = "MY_SECRET_KEY";
        HashCodec<?> codec = HashCodec.HS256(secret.getBytes());

        JWSSerializer.JWS jws = new JWTBuilder()
                .expiresIn(1)
                .signed(codec);

        String ser = jws.asString().getOrThrow();

        JWT parsed = JWSSerializer.read(ser, codec).getOrThrow();
        Assertions.assertFalse(parsed.isExpired());
    }

}
