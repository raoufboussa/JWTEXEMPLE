package dz.teletic.lunch.security.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Component
public class TokenHelper {

    private final Logger log = LoggerFactory.getLogger(TokenHelper.class);

    public static final String AUDIENCE = "web";

    @Value("${app.name}")
    private String APP_NAME;

    @Value("${jwt.secret}")
    public String SECRET;

    @Value("${jwt.expires_in}")
    private long EXPIRES_IN;

    @Value("${jwt.refreshed_time_lapse}")
    private long REFRESHED_TIME_LAPSE;

    @Value("${jwt.header}")
    private String AUTH_HEADER;

    private SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.HS512;

    public String generateToken(String username, List<String> roles, boolean isPasswordChanged, String fullName, String email) {
        long now = new Date().getTime();
        Date expiresIn = new Date(now + EXPIRES_IN * 1000);

        return Jwts.builder()
                .setIssuer(APP_NAME)
                .setSubject(username)
                .setAudience(AUDIENCE)
                .setIssuedAt(new Date())
                .setExpiration(expiresIn)
                .claim("passwordChanged", isPasswordChanged)
                .claim("roles", roles)
                .claim("fullName", fullName)
                .claim("email", email)
                .signWith(SIGNATURE_ALGORITHM, SECRET)
                .compact();
    }

    public Boolean isValideToken(String token, UserDetails userDetails) {
        final Optional<Claims> claims = getAllClaimsFromToken(token);

        if (!claims.isPresent()) return false;

        String username = claims.get().getSubject();

        return userDetails.getUsername().equals(username)
                && userDetails.isEnabled()
                && !isTokenExpired(claims.get());
    }

    public Optional<String> getToken(HttpServletRequest request) {
        String authHeader = request.getHeader(AUTH_HEADER);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return Optional.of(authHeader.substring(7));
        }

        return Optional.empty();
    }

    public String refreshToken(String token) {
        String refreshedToken = null;
        Date now = new Date();
        Date expiresIn = new Date(now.getTime() + EXPIRES_IN * 1000);

        try {
            final Optional<Claims> claimsOp = getAllClaimsFromToken(token);
            if (claimsOp.isPresent()) {
                Claims claims = claimsOp.get();
                claims.setIssuedAt(now);
                refreshedToken = Jwts.builder()
                        .setClaims(claims)
                        .setExpiration(expiresIn)
                        .signWith(SIGNATURE_ALGORITHM, SECRET)
                        .compact();
            }
        } catch (Exception e) {
            log.error("refreshToken : {}, {}", token, e.getMessage());
        }

        return refreshedToken;
    }

    public boolean isTokenRefreshable(String token) {
        Optional<Claims> claims = getAllClaimsFromToken(token);

        if (!claims.isPresent()) return false;

        long currentTime = new Date().getTime();
        long expiryTime = claims.get().getExpiration().getTime();

        return (currentTime > expiryTime) && (currentTime < (expiryTime + (REFRESHED_TIME_LAPSE * 1000)));
    }

    private Optional<Claims> getAllClaimsFromToken(String token) {
        Claims claims = null;
        try {
            claims = Jwts.parser()
                    .setSigningKey(SECRET)
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            claims = e.getClaims();
        } catch (Exception e) {
            log.error("getAllClaimsFromToken : {}, {}", token, e.getMessage());
        }

        return Optional.ofNullable(claims);
    }

    public Optional<String> getUsernameFromToken(String token) {
        String username = null;
        try {
            final Optional<Claims> claims = getAllClaimsFromToken(token);
            if (claims.isPresent()) {
                username = claims.get().getSubject();
            }
        } catch (Exception e) {
            log.error("getUsernameFromToken : {}, {}", token, e.getMessage());
        }

        return Optional.ofNullable(username);
    }

    public boolean isTokenExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }

    public long getExpiredIn() {
        return EXPIRES_IN;
    }
}
