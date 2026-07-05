package secureAuth.pro.domain.enums;

public enum AuditAction {
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    LOGOUT,
    TOKEN_ISSUED,
    TOKEN_REFRESHED,
    TOKEN_REVOKED,
    TOKEN_REUSE_DETECTED,
    MFA_ENABLED,
    MFA_DISABLED,
    CLIENT_CREATED,
    RATE_LIMIT_EXCEEDED,
}
