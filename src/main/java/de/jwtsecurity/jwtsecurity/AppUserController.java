package de.jwtsecurity.jwtsecurity;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
}
