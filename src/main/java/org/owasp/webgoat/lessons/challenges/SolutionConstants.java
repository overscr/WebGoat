/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges;

import java.security.SecureRandom;

public interface SolutionConstants {

  // The "!!webgoat_admin_1234!!" shape of the password is documented and well known, so anyone
  // who has read about this lesson only needs the 4-digit pin hidden in the challenge image to
  // log in as admin. A random suffix generated fresh on every boot is appended so the full
  // password can never be reconstructed from public material alone, even once the pin is known.
  // The suffix is letters only so it can never itself contain the "1234" placeholder that gets
  // substituted for the pin.
  String PASSWORD = "!!webgoat_admin_1234!!_" + randomSuffix();

  static String randomSuffix() {
    String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    SecureRandom random = new SecureRandom();
    StringBuilder suffix = new StringBuilder(20);
    for (int i = 0; i < 20; i++) {
      suffix.append(alphabet.charAt(random.nextInt(alphabet.length())));
    }
    return suffix.toString();
  }
}
