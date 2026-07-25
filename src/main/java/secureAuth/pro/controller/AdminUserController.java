package secureAuth.pro.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin/users")
public class AdminUserController {
    @GetMapping
    @PreAuthorize("hasAuthority('user:read')")
    public List<String> list() {
        return List.of("admin", "user");
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('user:delete')")
    public void delete(@PathVariable String id) {

    }
}
