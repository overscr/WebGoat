/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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

  // A reversible hex encoding is not authentication: anyone holding one cookie could decode it,
  // change the plaintext to a different username and re-encode it into a cookie for another
  // account. The value is now bound with a keyed HMAC generated fresh at startup, so a cookie
  // cannot be forged without that server-only key, and altering either half invalidates it.
  private static final String HMAC_ALGORITHM = "HmacSHA256";
  private static final SecretKeySpec HMAC_KEY = newSigningKey();
  private static final String FIELD_SEPARATOR = "|";

  private EncDec() {}

  public static String encode(final String value) {
    if (value == null) {
      return null;
    }

    String data = toBase64(value.toLowerCase());
    String tag = toBase64(sign(data));
    return data + FIELD_SEPARATOR + tag;
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }

    String[] parts = encodedValue.split("\\" + FIELD_SEPARATOR, 2);
    if (parts.length != 2) {
      throw new IllegalArgumentException("Cookie is not valid");
    }

    String data = parts[0];
    byte[] expectedTag = sign(data);
    byte[] actualTag = fromBase64(parts[1]);
    if (!MessageDigest.isEqual(expectedTag, actualTag)) {
      throw new IllegalArgumentException("Cookie is not valid");
    }
    return new String(fromBase64(data), StandardCharsets.UTF_8);
  }

  private static byte[] sign(String data) {
    try {
      Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
      hmac.init(HMAC_KEY);
      return hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new IllegalStateException("Could not sign cookie value", e);
    }
  }

  private static String toBase64(String plain) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
  }

  private static byte[] fromBase64(String encoded) {
    return Base64.getUrlDecoder().decode(encoded);
  }

  private static SecretKeySpec newSigningKey() {
    byte[] rawKey = new byte[32];
    new SecureRandom().nextBytes(rawKey);
    return new SecretKeySpec(rawKey, HMAC_ALGORITHM);
  }
}
