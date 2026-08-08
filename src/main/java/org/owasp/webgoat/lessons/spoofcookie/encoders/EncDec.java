/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
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

  /*
   * The cookie is only encoded, so it has to be authenticated as well. Without a keyed MAC anyone
   * who obtains a cookie can decode it and mint a cookie for another user.
   */
  private static final String MAC_ALGORITHM = "HmacSHA256";
  private static final byte[] MAC_KEY = generateKey();
  private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder DECODER = Base64.getUrlDecoder();
  private static final char SEPARATOR = '.';

  private EncDec() {}

  public static String encode(final String value) {
    if (value == null) {
      return null;
    }

    String payload = ENCODER.encodeToString(value.toLowerCase().getBytes(StandardCharsets.UTF_8));
    return payload + SEPARATOR + ENCODER.encodeToString(mac(payload));
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }

    int separatorIndex = encodedValue.lastIndexOf(SEPARATOR);
    if (separatorIndex < 0) {
      throw new IllegalArgumentException("Cookie is not valid");
    }

    String payload = encodedValue.substring(0, separatorIndex);
    byte[] providedMac = DECODER.decode(encodedValue.substring(separatorIndex + 1));
    if (!MessageDigest.isEqual(mac(payload), providedMac)) {
      throw new IllegalArgumentException("Cookie is not valid");
    }

    return new String(DECODER.decode(payload), StandardCharsets.UTF_8);
  }

  private static byte[] mac(final String payload) {
    try {
      Mac mac = Mac.getInstance(MAC_ALGORITHM);
      mac.init(new SecretKeySpec(MAC_KEY, MAC_ALGORITHM));
      return mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Unable to authenticate the cookie", e);
    }
  }

  private static byte[] generateKey() {
    byte[] key = new byte[32];
    new SecureRandom().nextBytes(key);
    return key;
  }
}
