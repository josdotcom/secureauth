package secureAuth.pro.security;


import java.util.UUID;

public sealed interface AuthResult
        permits AuthResult.Success, AuthResult.MfaRequired, AuthResult.Failure {

    record Success(UUID userId) implements AuthResult {}

    record MfaRequired(UUID userId) implements AuthResult {}

    record Failure(UUID userId) implements AuthResult {}
}
