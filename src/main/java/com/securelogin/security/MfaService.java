package com.securelogin.security;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;

@Service
public class MfaService {

    private final PasswordHashingService passwordHashingService;

    @Value("${app.security.mfa.issuer:SecureLoginApp}")
    private String issuer;

    private SecretGenerator secretGenerator;
    private CodeVerifier codeVerifier;
    private CodeGenerator codeGenerator;

    public MfaService(PasswordHashingService passwordHashingService) {
        this.passwordHashingService = passwordHashingService;
    }

    @PostConstruct
    public void init() {
        TimeProvider timeProvider = new SystemTimeProvider();
        this.secretGenerator = new DefaultSecretGenerator();
        this.codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1);
        this.codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
    }

    public String generateSecret() {
        return secretGenerator.generate();
    }

    public boolean verifyCode(String secret, String code) {
        return codeVerifier.isValidCode(secret, code);
    }

    public String getQrCodeContent(String secret, String username) {
        StringBuilder sb = new StringBuilder();
        sb.append("otpauth://totp/");
        sb.append(java.net.URLEncoder.encode(issuer + ":" + username, java.nio.charset.StandardCharsets.UTF_8));
        sb.append("?secret=").append(secret);
        sb.append("&issuer=").append(java.net.URLEncoder.encode(issuer, java.nio.charset.StandardCharsets.UTF_8));
        sb.append("&algorithm=SHA1");
        sb.append("&digits=6");
        sb.append("&period=30");
        return sb.toString();
    }
}
