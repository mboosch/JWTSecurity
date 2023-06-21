package de.jwtsecurity.jwtsecurity;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AppUserService {
    @Value("jwt.secret")
    private String secret;
    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenRepository tokenRepository;
    int tokenExpirationTime = 15;

    public AppUser createUser(AppUser appUser) {
        if (appUserRepository.findByUsername(appUser.getUsername()).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT);
        }
        appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
        appUser.setRole("BASIC");

        appUserRepository.save(appUser);
        appUser.setPassword("");
        return appUser;
    }

    public LoginResponse login(LoginRequest loginrequest) {
        final Instant now = Instant.now();
        Optional<AppUser> optionalAppUser = appUserRepository.findByUsername(loginrequest.getUsername());
        if (optionalAppUser.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        AppUser appUser = optionalAppUser.get();

        if (!passwordEncoder.matches(loginrequest.getPassword(), appUser.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        try {
            Algorithm algorithm = Algorithm.HMAC512(secret);
            String token = JWT.create()
                    .withClaim("id", appUser.getId())
                    .withClaim("username", appUser.getUsername())
                    .withIssuedAt(Date.from(now))
                    .withExpiresAt(Date.from(now.plus(tokenExpirationTime, ChronoUnit.MINUTES)))
                    .sign(algorithm);
            return new LoginResponse(token);
        } catch (JWTCreationException exception) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
    }

    public Optional<AppUser> findUserById(String userId) {
        return appUserRepository.findById(userId);
    }

    public void logout() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthentication) {
            String jwtToken = ((JwtAuthentication) authentication).getCredentials();
            blacklistToken(jwtToken);
        }
    }

    public void blacklistToken(String token) {
        final Instant now = Instant.now();
        tokenRepository.save(new Token(UUID.randomUUID().toString(), token, now));
    }

    public boolean isTokenBlacklisted(String jwtToken) {
        Optional<Token> dataBaseResponse = tokenRepository.findByTokenEquals(jwtToken);
        return dataBaseResponse.isPresent();
    }

    public void cleanBlackList() {
        final Instant now = Instant.now();
        List<Token> tokenList = tokenRepository.findAll();
        if (!tokenList.isEmpty()) {
            for (Token tokenToTest : tokenList) {
                if (now.compareTo(tokenToTest.getIssuedAt().plus(tokenExpirationTime, ChronoUnit.MINUTES)) > 0) {
                    tokenRepository.delete(tokenToTest);
                }
            }
        }
    }

}