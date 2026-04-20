package com.securelogin.controller;

import com.securelogin.dto.ApiResponse;
import com.securelogin.entity.User;
import com.securelogin.repository.UserRepository;
import com.securelogin.security.MfaService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth/mfa")
@RequiredArgsConstructor
public class MfaController {

    private final MfaService mfaService;
    private final UserRepository userRepository;

    @PostMapping("/setup")
    public ResponseEntity<ApiResponse<MfaSetupResponse>> setupMfa(HttpSession session) {
        Long userId = (Long) session.getAttribute("userId");
        if (userId == null) {
            return ResponseEntity.status(401)
                .body(ApiResponse.error("Unauthorized"));
        }

        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("User not found"));

        String secret = mfaService.generateSecret();
        String qrCodeUri = mfaService.getQrCodeContent(secret, user.getUsername());

        return ResponseEntity.ok(ApiResponse.success("MFA setup generated", 
            new MfaSetupResponse(secret, qrCodeUri)));
    }

    @PostMapping("/verify-setup")
    public ResponseEntity<ApiResponse<Void>> verifyMfaSetup(
            @RequestBody MfaVerifyRequest request,
            HttpSession session) {
        Long userId = (Long) session.getAttribute("userId");
        if (userId == null) {
            return ResponseEntity.status(401)
                .body(ApiResponse.error("Unauthorized"));
        }

        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("User not found"));

        if (!mfaService.verifyCode(request.getSecret(), request.getCode())) {
            return ResponseEntity.badRequest()
                .body(ApiResponse.error("Invalid verification code"));
        }

        user.setMfaSecret(request.getSecret());
        user.setMfaEnabled(true);
        userRepository.save(user);

        return ResponseEntity.ok(ApiResponse.success("MFA enabled successfully"));
    }

    @PostMapping("/disable")
    public ResponseEntity<ApiResponse<Void>> disableMfa(
            @RequestBody MfaDisableRequest request,
            HttpSession session) {
        Long userId = (Long) session.getAttribute("userId");
        if (userId == null) {
            return ResponseEntity.status(401)
                .body(ApiResponse.error("Unauthorized"));
        }

        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("User not found"));

        if (!mfaService.verifyCode(user.getMfaSecret(), request.getCode())) {
            return ResponseEntity.badRequest()
                .body(ApiResponse.error("Invalid verification code"));
        }

        user.setMfaEnabled(false);
        user.setMfaSecret(null);
        userRepository.save(user);

        return ResponseEntity.ok(ApiResponse.success("MFA disabled successfully"));
    }

    @lombok.Data
    private static class MfaSetupResponse {
        private final String secret;
        private final String qrCodeUri;
    }

    @lombok.Data
    private static class MfaVerifyRequest {
        private String secret;
        private String code;
    }

    @lombok.Data
    private static class MfaDisableRequest {
        private String code;
    }
}
