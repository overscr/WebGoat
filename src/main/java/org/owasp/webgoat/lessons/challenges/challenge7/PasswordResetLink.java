/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import java.security.SecureRandom;
import java.util.Random;

/**
 * WARNING: DO NOT CHANGE FILE WITHOUT CHANGING .git contents
 *
 * @author nbaars
 * @since 8/17/17.
 */
public class PasswordResetLink {

  public String createPasswordReset(String username, String key) {
    // The admin reset link used to be generated with the PRNG re-seeded to the length of a
    // hardcoded key ("webgoat".length() == 7), making it the exact same predictable value on
    // every single run. Combined with the source disclosure at /challenge/7/.git, anyone could
    // read this algorithm, recompute that fixed value offline and reset the admin account
    // without ever seeing the actual e-mail. Every reset link - admin's included - now comes from
    // a non-deterministic, cryptographically strong random source, so it can no longer be
    // predicted even with full knowledge of this source file.
    Random random = new SecureRandom();
    return scramble(random, scramble(random, scramble(random, MD5.getHashString(username))));
  }

  public static String scramble(Random random, String inputString) {
    char[] a = inputString.toCharArray();
    for (int i = 0; i < a.length; i++) {
      int j = random.nextInt(a.length);
      char temp = a[i];
      a[i] = a[j];
      a[j] = temp;
    }
    return new String(a);
  }

  public static void main(String[] args) {
    if (args == null || args.length != 2) {
      System.out.println("Need a username and key");
      System.exit(1);
    }
    String username = args[0];
    String key = args[1];
    System.out.println("Generation password reset link for " + username);
    System.out.println(
        "Created password reset link: "
            + new PasswordResetLink().createPasswordReset(username, key));
  }
}
