/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.springframework.http.ResponseEntity.ok;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.RandomStringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "jwt-refresh-hint1",
  "jwt-refresh-hint2",
  "jwt-refresh-hint3",
  "jwt-refresh-hint4"
})
public class JWTRefreshEndpoint implements AssignmentEndpoint {

  public static final String PASSWORD = "bm5nhSkxCXZkKRy4";
  /**
   * The old signing key was a short literal sitting one character away from the demo password
   * printed in the lesson, so anyone could re-sign a token. It is regenerated from {@link
   * SecureRandom} on every boot.
   */
  private static final String JWT_PASSWORD = generateSigningSecret();

  /** Refresh tokens are recorded against the account they were minted for. */
  private static final Map<String, String> refreshTokenOwners = new ConcurrentHashMap<>();

  private static String generateSigningSecret() {
    byte[] material = new byte[64];
    new SecureRandom().nextBytes(material);
    return Base64.getEncoder().encodeToString(material);
  }

  @PostMapping(
      value = "/JWT/refresh/login",
      consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public ResponseEntity follow(@RequestBody(required = false) Map<String, Object> json) {
    if (json == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    String user = (String) json.get("user");
    String password = (String) json.get("password");

    if ("Jerry".equalsIgnoreCase(user) && PASSWORD.equals(password)) {
      return ok(createNewTokens(user));
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  }

  private Map<String, Object> createNewTokens(String user) {
    Map<String, Object> claims = Map.of("admin", "false", "user", user);
    String token =
        Jwts.builder()
            .setIssuedAt(new Date(System.currentTimeMillis() + TimeUnit.DAYS.toDays(10)))
            .setClaims(claims)
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, JWT_PASSWORD)
            .compact();
    Map<String, Object> tokenJson = new HashMap<>();
    String refreshToken = RandomStringUtils.randomAlphabetic(20);
    refreshTokenOwners.put(refreshToken, user);
    tokenJson.put("access_token", token);
    tokenJson.put("refresh_token", refreshToken);
    return tokenJson;
  }

  @PostMapping("/JWT/refresh/checkout")
  @ResponseBody
  public ResponseEntity<AttackResult> checkout(
      @RequestHeader(value = "Authorization", required = false) String token) {
    if (token == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    try {
      // parseClaimsJws will not accept a token whose header says "alg":"none": an unsigned
      // token is now an invalid token rather than a token that happens to skip verification.
      Jws<Claims> jwt =
          Jwts.parser().setSigningKey(JWT_PASSWORD).parseClaimsJws(token.replace("Bearer ", ""));
      Claims claims = jwt.getBody();
      String user = (String) claims.get("user");
      if ("Tom".equals(user)) {
        return ok(success(this).build());
      }
      return ok(failed(this).feedback("jwt-refresh-not-tom").feedbackArgs(user).build());
    } catch (ExpiredJwtException e) {
      return ok(failed(this).output(e.getMessage()).build());
    } catch (JwtException e) {
      return ok(failed(this).feedback("jwt-invalid-token").build());
    }
  }

  @PostMapping("/JWT/refresh/newToken")
  @ResponseBody
  public ResponseEntity newToken(
      @RequestHeader(value = "Authorization", required = false) String token,
      @RequestBody(required = false) Map<String, Object> json) {
    if (token == null || json == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    String user;
    String refreshToken;
    try {
      Jws<Claims> jwt =
          Jwts.parser().setSigningKey(JWT_PASSWORD).parseClaimsJws(token.replace("Bearer ", ""));
      user = (String) jwt.getBody().get("user");
      refreshToken = (String) json.get("refresh_token");
    } catch (ExpiredJwtException e) {
      // An expired access token may still be exchanged, but only its signature-backed claims
      // are trusted; e.getClaims() is only populated once the signature has been checked.
      user = (String) e.getClaims().get("user");
      refreshToken = (String) json.get("refresh_token");
    }

    if (user == null || refreshToken == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    // A refresh token may only renew the session it was issued for. Presenting somebody else's
    // access token alongside your own refresh token no longer mints a token for that account.
    if (!user.equals(refreshTokenOwners.get(refreshToken))) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    refreshTokenOwners.remove(refreshToken);
    return ok(createNewTokens(user));
  }
}
