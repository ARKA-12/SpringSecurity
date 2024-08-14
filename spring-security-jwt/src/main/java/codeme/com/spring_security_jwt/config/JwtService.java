package codeme.com.spring_security_jwt.config;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

public class JwtService {

    private static final String SECRET_KEY = "18100e219d3c52948974e8a4cd24a7cf7b275e3762b9793fdb095b3eec8a8eab";

    public String extarctUsername(String token) {

        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {

        return generateToken(new HashMap<>(), userDetails);

    }

    //generate Token
    public String generateToken(Map<String, Object> extraClaims, UserDetails UserDetails) {

        return Jwts
                .builder()
                .claims(extraClaims)
                .subject(UserDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60))
                .signWith(getVerifyKey(), Jwts.SIG.HS256)
                .compact();
    }

    public boolean isTokenValid(UserDetails userDetails, String token) {

        String username = extarctUsername(userDetails.getUsername());

        return (username.equals(token) && !isTokenExpired(token));

    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());

    }

    public Date extractExpiration(String token) {

        return extractClaim(token, Claims::getExpiration);
    }

    @SuppressWarnings("deprecation")
    private Claims extractAllClaims(String token) {

        return Jwts
                .parser()
                .verifyWith(getVerifyKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private SecretKey getVerifyKey() {

        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);

        return Keys.hmacShaKeyFor(keyBytes);

    }

}
