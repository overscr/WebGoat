/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

public class EncDec {

  // The previous scheme was reverse-then-hex-then-base64 around a constant salt. None of that
  // is a secret the holder of a cookie does not also hold: the transformation is invertible
  // without any key, so a visitor could decode their own cookie, substitute another account's
  // name and re-encode it. The value is now accompanied by a keyed MAC computed with material
  // that never leaves the server, so an altered cookie no longer verifies.

  private static final String MAC_ALGORITHM = "HmacSHA256";
  private static final byte[] SIGNING_KEY = newSigningKey();
  private static final String SEPARATOR = ".";

  private EncDec() {}

  public static String encode(final String value) {
    if (value == null) {
      return null;
    }

    String subject = base64UrlEncode(value.toLowerCase().getBytes(StandardCharsets.UTF_8));
    return subject + SEPARATOR + authenticationTag(subject);
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }

    int separator = encodedValue.lastIndexOf(SEPARATOR);
    if (separator < 1 || separator == encodedValue.length() - 1) {
      throw new IllegalArgumentException("Invalid authentication cookie");
    }

    String subject = encodedValue.substring(0, separator);
    String presentedTag = encodedValue.substring(separator + 1);
    // Constant-time comparison: the answer must not leak through how long it took to reach it.
    if (!MessageDigest.isEqual(
        presentedTag.getBytes(StandardCharsets.UTF_8),
        authenticationTag(subject).getBytes(StandardCharsets.UTF_8))) {
      throw new IllegalArgumentException("Invalid authentication cookie");
    }

    return new String(Base64.getUrlDecoder().decode(subject), StandardCharsets.UTF_8);
  }

  private static String authenticationTag(final String subject) {
    try {
      Mac mac = Mac.getInstance(MAC_ALGORITHM);
      mac.init(new SecretKeySpec(SIGNING_KEY, MAC_ALGORITHM));
      return base64UrlEncode(mac.doFinal(subject.getBytes(StandardCharsets.UTF_8)));
    } catch (Exception e) {
      throw new IllegalArgumentException("Invalid authentication cookie");
    }
  }

  private static String base64UrlEncode(final byte[] value) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
  }

  private static byte[] newSigningKey() {
    byte[] key = new byte[32];
    new SecureRandom().nextBytes(key);
    return key;
  }
}
