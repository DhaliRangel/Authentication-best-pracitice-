package com.securelogin.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${app.email.from}")
    private String fromEmail;

    public void sendPasswordResetEmail(String to, String token) {
        String resetLink = "https://yourapp.com/reset-password?token=" + token;
        
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(to);
        message.setSubject("Password Reset Request");
        message.setText(buildPasswordResetEmail(resetLink));
        
        mailSender.send(message);
        log.info("Password reset email sent to {}", maskEmail(to));
    }

    public void sendNewLoginNotification(String to, String ipAddress, String userAgent) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(to);
        message.setSubject("New Login Detected");
        message.setText(buildNewLoginEmail(ipAddress, userAgent));
        
        mailSender.send(message);
        log.info("New login notification sent to {}", maskEmail(to));
    }

    private String buildPasswordResetEmail(String resetLink) {
        return String.format("""
            You requested a password reset for your account.
            
            Click the link below to reset your password:
            %s
            
            This link will expire in 15 minutes.
            
            If you didn't request this, please ignore this email and your password will remain unchanged.
            
            For security, please do not share this email with anyone.
            """, resetLink);
    }

    private String buildNewLoginEmail(String ipAddress, String userAgent) {
        return String.format("""
            A new login was detected on your account.
            
            IP Address: %s
            Device: %s
            
            If this was you, you can ignore this email.
            
            If this wasn't you, please secure your account immediately by:
            1. Changing your password
            2. Enabling two-factor authentication
            3. Reviewing your active sessions
            """, ipAddress, userAgent);
    }

    private String maskEmail(String email) {
        if (email == null || email.length() < 4) {
            return "***";
        }
        int atIndex = email.indexOf('@');
        if (atIndex <= 2) {
            return email.substring(0, 1) + "***" + email.substring(atIndex);
        }
        return email.substring(0, 2) + "***" + email.substring(atIndex);
    }
}
