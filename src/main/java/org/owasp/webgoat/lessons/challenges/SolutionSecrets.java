/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges;

import java.security.SecureRandom;
import java.util.Base64;

/** Produces the per-boot secrets the challenge lessons rely on. */
final class SolutionSecrets {

  private SolutionSecrets() {}

  static String newAdminPassword() {
    byte[] material = new byte[24];
    new SecureRandom().nextBytes(material);
    return "!!webgoat_admin_" + Base64.getUrlEncoder().withoutPadding().encodeToString(material);
  }
}
