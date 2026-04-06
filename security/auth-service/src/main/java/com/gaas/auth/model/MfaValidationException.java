package com.gaas.auth.model;

/**
 * ============================================================
 * MFA Validation Exception
 * ============================================================
 *
 * PURPOSE:
 *   Thrown when a token request requires Multi-Factor Authentication (MFA)
 *   but the IdP token's `amr` (Authentication Methods References) claim
 *   does not contain an MFA factor.
 *
 * WHEN THIS IS THROWN:
 *   In IdpTokenService.validateMfaForHighPrivilegeScopes() when:
 *     1. A user requests a high-privilege scope (e.g., gateway:admin, api:write)
 *     2. The scope is in gaas.idp.high-privilege-scopes configuration
 *     3. The IdP token's `amr` claim contains ONLY ["pwd"] (password only, no MFA)
 *
 * MFA FACTORS THAT PREVENT THIS EXCEPTION (amr values that count as MFA):
 *   "otp"  — Time-based OTP (TOTP/HOTP via Google Authenticator, Authy, etc.)
 *   "totp" — Same as "otp" (different IdPs use different labels)
 *   "mfa"  — Generic MFA completed (some IdPs use this umbrella term)
 *   "hwk"  — Hardware key (WebAuthn/FIDO2 hardware security key)
 *   "face" — Biometric authentication (TouchID, FaceID via WebAuthn)
 *
 * HOW CALLERS HANDLE THIS:
 *   TokenController.issueToken():
 *     Returns HTTP 403 with:
 *       {"error": "mfa_required",
 *        "error_description": "MFA required for scope: gateway:admin",
 *        "mfa_scope": "gateway:admin"}
 *
 *   AuthorizationController.handleCallback():
 *     Returns HTTP 403 with the same structure.
 *     The client should redirect the user back to the IdP with an
 *     explicit acr_values=mfa or step-up authentication request.
 *
 * WHY A CHECKED EXCEPTION IS NOT USED:
 *   This exception flows through the Spring MVC call stack and is caught
 *   in the controller layer. Making it unchecked (extends RuntimeException)
 *   means the service layer doesn't need try/catch everywhere — the
 *   exception propagates naturally to the controller's catch block.
 *
 * EXTENSION POINT:
 *   Future versions could add:
 *   - requiredAcr (Authentication Context Class Reference level required)
 *   - userId (for audit logging which user was denied)
 *   - challenge hint (URL for step-up auth re-initiation)
 */
public class MfaValidationException extends RuntimeException {

    /**
     * The specific OAuth scope that triggered the MFA requirement.
     * Examples: "gateway:admin", "api:write"
     * Included in the HTTP 403 response body so the client knows WHICH scope
     * caused the error — useful when multiple scopes were requested.
     */
    private final String requiredScope;

    /**
     * Creates an MfaValidationException indicating which scope needs MFA.
     *
     * @param message      Human-readable description of why MFA is required
     *                     (included in logs and error responses)
     * @param requiredScope The OAuth scope that requires MFA
     *                     (returned in the HTTP 403 error body as "mfa_scope")
     */
    public MfaValidationException(String message, String requiredScope) {
        super(message);
        this.requiredScope = requiredScope;
    }

    /**
     * Returns the OAuth scope that triggered the MFA requirement.
     * Used by controllers to include the scope in the HTTP 403 response body.
     */
    public String getRequiredScope() {
        return requiredScope;
    }
}
