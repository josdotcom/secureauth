package secureAuth.pro.dto;

import jakarta.validation.constraints.NotNull;

import java.util.Map;

public record ErrorResponse(
        int status,
        String error,
        String message,
        Map<String, String> fieldErrors
) {}
