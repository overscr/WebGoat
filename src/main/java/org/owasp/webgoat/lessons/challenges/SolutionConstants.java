/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges;

public interface SolutionConstants {

  /**
   * The administrator credential used to be a literal in the source, so it was known to anyone
   * who read the repository and identical on every deployment. It is generated from {@link
   * java.security.SecureRandom} when the server starts and never written down anywhere else.
   */
  String PASSWORD = SolutionSecrets.newAdminPassword();
}
