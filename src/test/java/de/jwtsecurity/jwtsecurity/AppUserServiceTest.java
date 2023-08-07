package de.jwtsecurity.jwtsecurity;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AppUserServiceTest {

    @InjectMocks
    private AppUserService testAppUserService;

    @Mock
    private AppUserRepository testAppUserRepository;

    @Mock
    private PasswordEncoder testPasswordEncoder;

    @Mock
    private TokenRepository testTokenRepository;

    @Mock
    private SecurityContext testSecurityContext;

    @Mock
    private JwtAuthentication testJwtAuthentication;

    private LoginRequest loginRequest;
    private AutoCloseable closeable;

    @BeforeEach
    public void setUp() {
        closeable = MockitoAnnotations.openMocks(this);
        testAppUserService = new AppUserService(testAppUserRepository, testPasswordEncoder, testTokenRepository);
        testAppUserService.setSecret("testSecret");
        loginRequest = new LoginRequest("testUser", "testPassword");
    }

    @AfterEach
    public void cleanup() throws Exception {
        closeable.close();
        SecurityContextHolder.clearContext();
    }

    AppUser testAppUser = new AppUser("", "testUser", "testPasswort", "BASIC");
    AppUser testAppUserReturnedByDatabase = new AppUser("1", "testUser", "encodedTestPassword", "BASIC");

    @Test
    public void createUserReturnsCorrectAppUserWhenGivenNotExistingUsername() {
        when(testAppUserRepository.findByUsername(anyString())).thenReturn(Optional.empty());
        when(testPasswordEncoder.encode(anyString())).thenReturn("$2a$10$F5krplpCN3he9LS49LfCxen6sXPb5x5XNsbI6ExPqNJHWyTTtXl8C");

        AppUser expected = new AppUser("", "testUser", "", "BASIC");
        AppUser actual = testAppUserService.createUser(testAppUser);

        assertEquals(expected, actual);
        verify(testAppUserRepository).findByUsername("testUser");
        verify(testAppUserRepository).save(any());
    }

    @Test
    public void createUserThrowsResponseStatusExceptionIfUsernameExists() {
        when(testAppUserRepository.findByUsername(anyString())).thenReturn(Optional.of(new AppUser()));

        assertThrows(ResponseStatusException.class, () -> testAppUserService.createUser(testAppUser));
    }

    @Test
    public void loginReturnsCorrectTokenIfUserFound() {
        when(testAppUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testAppUserReturnedByDatabase));
        when(testPasswordEncoder.matches("testPassword", "encodedTestPassword")).thenReturn(true);

        LoginResponse response = testAppUserService.login(loginRequest);
        assertNotNull(response.getToken());
        assertFalse(response.getToken().isEmpty());
    }

    @Test
    public void loginReturnsUnauthorizedIfUserNotFound() {
        when(testAppUserRepository.findByUsername(any(String.class))).thenReturn(Optional.empty());
        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> testAppUserService.login(loginRequest));
        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
    }

    @Test
    public void loginReturnsUnauthorizedIfPasswordIncorrect() {
        when(testAppUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testAppUserReturnedByDatabase));
        when(testPasswordEncoder.matches("testPassword", "encodedTestPassword")).thenReturn(false);

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> testAppUserService.login(loginRequest));
        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
    }

    @Test
    public void loginReturnsUnauthorizedIfCreationOfTokenFailed() {
        when(testAppUserRepository.findByUsername("testUser")).thenReturn(Optional.of(testAppUserReturnedByDatabase));
        when(testPasswordEncoder.matches("testPassword", "encodedTestPassword")).thenReturn(true);
        testAppUserService.setSecret(null);

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> testAppUserService.login(loginRequest));
        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode());
    }

    @Test
    void findUserByIdReturnsCorrectOptionalIfUserExists() {
        when(testAppUserRepository.findById("1")).thenReturn(Optional.of(testAppUserReturnedByDatabase));
        Optional<AppUser> expected = Optional.of(testAppUserReturnedByDatabase);
        Optional<AppUser> actual = testAppUserService.findUserById("1");
        Assertions.assertEquals(expected, actual);
    }

    @Test
    void findUserByIdReturnsEmptyOptionalIfUserNotFound() {
        when(testAppUserRepository.findById("1")).thenReturn(Optional.empty());
        Optional<AppUser> expected = Optional.empty();
        Optional<AppUser> actual = testAppUserService.findUserById("1");
        Assertions.assertEquals(expected, actual);
    }

    @Test
    void isTokenGettingOldReturnsFalseIfTokenIsNotOld() {
        when(testSecurityContext.getAuthentication()).thenReturn(testJwtAuthentication);
        when(testJwtAuthentication.getIssuedAt()).thenReturn(Optional.of(Instant.now().minus(4, ChronoUnit.MINUTES)));
        SecurityContextHolder.setContext(testSecurityContext);
        assertFalse(testAppUserService.isTokenGettingOld());
    }

    @Test
    void isTokenGettingOldReturnsTrueIfTokenIs5MinOld() {
        when(testSecurityContext.getAuthentication()).thenReturn(testJwtAuthentication);
        when(testJwtAuthentication.getIssuedAt()).thenReturn(Optional.of(Instant.now().minus(5, ChronoUnit.MINUTES)));
        SecurityContextHolder.setContext(testSecurityContext);
        assertTrue(testAppUserService.isTokenGettingOld());
    }

    @Test
    void isTokenGettingOldReturnsTrueIfTokenIsOld() {
        when(testSecurityContext.getAuthentication()).thenReturn(testJwtAuthentication);
        when(testJwtAuthentication.getIssuedAt()).thenReturn(Optional.of(Instant.now().minus(6, ChronoUnit.MINUTES)));
        SecurityContextHolder.setContext(testSecurityContext);
        assertTrue(testAppUserService.isTokenGettingOld());
    }

    @Test
    void isTokenGettingOldReturnsForbiddenIfIssuedAtIsEmpty() {
        when(testSecurityContext.getAuthentication()).thenReturn(testJwtAuthentication);
        when(testJwtAuthentication.getIssuedAt()).thenReturn(Optional.empty());
        SecurityContextHolder.setContext(testSecurityContext);
        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> testAppUserService.isTokenGettingOld());
        assertEquals(HttpStatus.FORBIDDEN, exception.getStatusCode());
    }
}