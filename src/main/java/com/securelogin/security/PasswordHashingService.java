package com.securelogin.security;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class PasswordHashingService {

    private final Argon2 argon2;
    private final SecretKey pepperKey;
    private final SecureRandom secureRandom;

    @Value("${app.security.argon2.memory:65536}")
    private int argon2Memory;

    @Value("${app.security.argon2.iterations:3}")
    private int argon2Iterations;

    @Value("${app.security.argon2.parallelism:4}")
    private int argon2Parallelism;

    @Value("${app.security.argon2.salt-length:32}")
    private int saltLength;

    @Value("${app.security.argon2.hash-length:32}")
    private int hashLength;

    public PasswordHashingService(@Value("${app.security.pepper}") String pepper) {
        this.argon2 = Argon2Factory.create();
        byte[] pepperBytes = sha256(pepper);
        this.pepperKey = new SecretKeySpec(pepperBytes, "AES");
        this.secureRandom = new SecureRandom();
    }

    public String generateSalt() {
        byte[] salt = new byte[saltLength];
        secureRandom.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    public String hashPassword(String password, String salt) {
        String pepperedPassword = applyPepper(password);
        return argon2.hash(argon2Iterations, argon2Memory, argon2Parallelism, pepperedPassword, StandardCharsets.UTF_8);
    }

    public boolean verifyPassword(String password, String salt, String storedHash) {
        String pepperedPassword = applyPepper(password);
        return argon2.verify(storedHash, pepperedPassword, StandardCharsets.UTF_8);
    }

    private String applyPepper(String password) {
        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, pepperKey);
            byte[] encrypted = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("Failed to apply pepper", e);
        }
    }

    private byte[] sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    public String generateSecureToken(int length) {
        byte[] tokenBytes = new byte[length];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }
}
