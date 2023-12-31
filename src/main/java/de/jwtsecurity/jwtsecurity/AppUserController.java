package de.jwtsecurity.jwtsecurity;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
@RequestMapping()
public class AppUserController {
    private final AppUserService appUserService;

    @PostMapping("/signup/")

    public AppUser createUser(@RequestBody AppUser appUser) {
        return appUserService.createUser(appUser);
    }

    @PostMapping("/login/")
    public LoginResponse login(@RequestBody LoginRequest loginrequest) {
        return appUserService.login(loginrequest);
    }

    @GetMapping("/logout/")
    public void logout() {
        appUserService.logout();
    }
}

