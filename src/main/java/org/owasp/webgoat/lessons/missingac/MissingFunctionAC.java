/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import java.security.SecureRandom;
import java.util.Base64;
import org.owasp.webgoat.container.lessons.Category;
import org.owasp.webgoat.container.lessons.Lesson;
import org.springframework.stereotype.Component;

@Component
public class MissingFunctionAC extends Lesson {

  // These salts used to be literal strings in the source, which means anyone who has read the
  // repository can recompute a user's hash offline without ever calling an endpoint that is
  // supposed to require the administrator role. Each salt is now drawn from a secure random
  // source once per boot, so the value is never predictable ahead of time.
  public static final String PASSWORD_SALT_SIMPLE = freshSalt();
  public static final String PASSWORD_SALT_ADMIN = freshSalt();

  private static String freshSalt() {
    byte[] bytes = new byte[24];
    new SecureRandom().nextBytes(bytes);
    return Base64.getEncoder().encodeToString(bytes);
  }

  @Override
  public Category getDefaultCategory() {
    return Category.A1;
  }

  @Override
  public String getTitle() {
    return "missing-function-access-control.title";
  }
}
