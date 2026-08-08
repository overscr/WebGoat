/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Issues and checks the one-time codes WebWolf hands to a user to prove they control the mailbox
 * or landing page a lesson sent them to. The old implementation derived the code by reversing the
 * WebGoat username, which is public and trivially reversible again - so the "secret" was really
 * just the username itself. A code minted here is unrelated to any identifier the user already
 * has: it comes from {@link SecureRandom}, lives only in server memory, and is scoped to a single
 * {@link Purpose} so a code obtained for one flow cannot be replayed against another.
 */
@Component
public class UniqueCodes {

  public enum Purpose {
    MAIL,
    PASSWORD_RESET
  }

  public static final String MAIL = Purpose.MAIL.name();
  public static final String PASSWORD_RESET = Purpose.PASSWORD_RESET.name();

  private static final int CODE_BYTES = 18;

  private final SecureRandom random = new SecureRandom();
  private final ConcurrentHashMap<String, String> issuedCodes = new ConcurrentHashMap<>();

  /** Returns the code issued to this user for this purpose, minting one on first use. */
  public String get(String username, String purpose) {
    return issuedCodes.computeIfAbsent(slot(username, purpose), ignored -> mint());
  }

  /** True when {@code submittedCode} is exactly the code previously issued for this slot. */
  public boolean matches(String username, String purpose, String submittedCode) {
    String issued = issuedCodes.get(slot(username, purpose));
    if (issued == null || submittedCode == null) {
      return false;
    }
    return MessageDigest.isEqual(
        issued.getBytes(StandardCharsets.UTF_8), submittedCode.getBytes(StandardCharsets.UTF_8));
  }

  private String slot(String username, String purpose) {
    return purpose + '#' + username;
  }

  private String mint() {
    byte[] raw = new byte[CODE_BYTES];
    random.nextBytes(raw);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
  }
}
