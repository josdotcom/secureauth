package secureAuth.pro.controller;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import secureAuth.pro.dto.LoginRequest;
import secureAuth.pro.dto.RegisterRequest;
import secureAuth.pro.dto.UserDto;
import secureAuth.pro.service.UserService;

import java.util.UUID;

@RestController
@RequestMapping("/api")
public class AuthController {
    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public UserDto register(@RequestHeader("X-Tenant-Id") UUID tenantId, @Valid @RequestBody RegisterRequest registerRequest) {
        return userService.register(tenantId, registerRequest.email(), registerRequest.password(), registerRequest.displayName());
    }

    @PostMapping("/login")
    public UserDto login(@RequestHeader("X-Tenant-Id") UUID tenantId, @Valid @RequestBody LoginRequest request) {
        return userService.authenticate(tenantId, request.email(), request.password());
    }
}
