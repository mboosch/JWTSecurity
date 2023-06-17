package de.jwtsecurity.jwtsecurity;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.*;

@RequiredArgsConstructor
public class JwtAuthentication implements Authentication {
    private final String jwtToken;
    private final AppUserService appUserService;
    private final String jwtSecret;
    private Optional<Map<String, Claim>> getJwtClaims() {
        DecodedJWT decodedJWT;
        try {
            Algorithm algorithm = Algorithm.HMAC512(jwtSecret);
            JWTVerifier verifier = JWT.require(algorithm).build();
            decodedJWT = verifier.verify(jwtToken);
            return Optional.of(decodedJWT.getClaims());
        } catch (JWTVerificationException exception){
            return Optional.empty();
        }
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return getJwtClaims().flatMap(
                claims -> appUserService.findUserById(claims.get("id").asString())
        ).map(
                appUser -> List.of(new SimpleGrantedAuthority(appUser.getRole()))).orElse(List.of());
    }

    @Override
    public String getCredentials() {
        return jwtToken;
    }

    @Override
    public Object getDetails() {
        return getJwtClaims().map(
                claims -> appUserService.findUserById(claims.get("id").asString())
        ).orElse(null);
    }

    @Override
    public Object getPrincipal() {
        return getJwtClaims().map(
                claims -> appUserService.findUserById(claims.get("id").asString())).orElse(null);
    }

    @Override
    public boolean isAuthenticated() {
        return getJwtClaims().isPresent();
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
    }

    @Override
    public String getName() {
        return getJwtClaims()
                .map(claims -> claims.get("username").asString())
                .orElse(null);
    }
}
