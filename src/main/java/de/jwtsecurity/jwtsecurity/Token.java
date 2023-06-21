package de.jwtsecurity.jwtsecurity;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.data.annotation.Id;

import java.time.Instant;

@AllArgsConstructor
@Data
public class Token {
    @Id
    String id;
    String token;
    Instant issuedAt;
}

