package secureAuth.pro.service;

import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.recovery.RecoveryCodeGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;
import secureAuth.pro.domain.MfaSecret;
import secureAuth.pro.domain.User;
import secureAuth.pro.exception.InvalidVerificationCodeException;
import secureAuth.pro.exception.MfaAlreadyEnabledException;
import secureAuth.pro.exception.MfaNotEnrolledException;
import secureAuth.pro.repository.MfaSecretRepository;
import secureAuth.pro.repository.UserRepository;
import secureAuth.pro.security.EncryptionService;
import secureAuth.pro.security.TokenHasher;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class MfaService {

    private static final String ISSUER = "SecureAuth";

    private final SecretGenerator secretGenerator;
    private final MfaSecretRepository mfaSecretRepository;
    private final UserRepository userRepository;
    private final RecoveryCodeGenerator recoveryCodeGenerator;
    private final CodeVerifier codeVerifier;
    private final EncryptionService encryptionService;

    public MfaService(UserRepository userRepository, SecretGenerator secretGenerator, MfaSecretRepository mfaSecretRepository, RecoveryCodeGenerator recoveryCodeGenerator, CodeVerifier codeVerifier, EncryptionService encryptionService) {
        this.userRepository = userRepository;
        this.secretGenerator = secretGenerator;
        this.mfaSecretRepository = mfaSecretRepository;
        this.recoveryCodeGenerator = recoveryCodeGenerator;
        this.codeVerifier = codeVerifier;
        this.encryptionService = encryptionService;
    }

    @Transactional
    public MfaEnrollmentResponse beginEnrollment(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found!" + userId));
        Optional<MfaSecret> existing = mfaSecretRepository.findByUser_Id(userId);
        if (existing.isPresent()) {
            MfaSecret current = existing.get();
            if (current.isConfirmed()) {
                throw new MfaAlreadyEnabledException("MFA is already enabled for this user");
            }

            mfaSecretRepository.delete(current);
            mfaSecretRepository.flush();
        }

        String secret = secretGenerator.generate();
        mfaSecretRepository.save(new MfaSecret(user, encryptionService.encrypt(secret), List.of()));

        QrData data = new QrData.Builder()
                .label(user.getEmail())
                .secret(secret)
                .issuer(ISSUER)
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();
        return new MfaEnrollmentResponse(secret, data.getUri());
    }

    @Transactional
    public List<String> confirmEnrollment(UUID userId, String code) {
        MfaSecret mfaSecret = mfaSecretRepository.findByUser_Id(userId)
                .orElseThrow(() -> new MfaNotEnrolledException("No Pending MFA enrollment for this user"));
        if (mfaSecret.isConfirmed()) {
            throw new MfaAlreadyEnabledException("MFA is already enabled for this user");
        }

        String secret = encryptionService.decrypt(mfaSecret.getEncryptedSecret());
        if (!codeVerifier.isValidCode(secret, code)) {
            throw new InvalidVerificationCodeException("Invalid verification code");
        }

        String[] rawCodes = recoveryCodeGenerator.generateCodes(10);
        List<String> hashes = Arrays.stream(rawCodes)
                .map(TokenHasher::sha256Hex)
                .toList();

        mfaSecret.confirm(hashes);
        mfaSecretRepository.save(mfaSecret);

        return List.of(rawCodes);
    }

    public boolean isMfaEnabled(UUID userId) {
        return mfaSecretRepository.findByUser_Id(userId)
                .map(MfaSecret::isConfirmed)
                .orElse(false);
    }

    @Transactional
    public boolean verifyLoginCode(UUID userId, String code) {
        MfaSecret mfa = mfaSecretRepository.findByUser_Id(userId)
                .orElseThrow(() -> new MfaNotEnrolledException("No MFA configured for this user"));

        String secret = encryptionService.decrypt(mfa.getEncryptedSecret());
        if (codeVerifier.isValidCode(secret, code)) {
            return true;
        }

        String hash = TokenHasher.sha256Hex(code);
        if(mfa.getRecoveryCodes().remove(hash)) {
            mfaSecretRepository.save(mfa);
            return true;
        }

        return false;
    }
    public record MfaEnrollmentResponse(String secret, String oauthUri) {};
}
