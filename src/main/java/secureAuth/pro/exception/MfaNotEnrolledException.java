package secureAuth.pro.exception;

public class MfaNotEnrolledException extends RuntimeException {
    public MfaNotEnrolledException(String message) {
        super(message);
    }
}
