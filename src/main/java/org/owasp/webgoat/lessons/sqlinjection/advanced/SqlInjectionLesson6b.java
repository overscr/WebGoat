/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SqlInjectionLesson6b implements AssignmentEndpoint {
  private static final String DAVE_USERNAME = "dave";
  private static final SecureRandom RANDOM = new SecureRandom();

  private final LessonDataSource dataSource;

  public SqlInjectionLesson6b(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjectionAdvanced/attack6b")
  @ResponseBody
  public AttackResult completed(@RequestParam String userid_6b) throws IOException {
    if (userid_6b.equals(getPassword())) {
      return success(this).build();
    }
    return failed(this).build();
  }

  protected String getPassword() {
    try (Connection connection = dataSource.getConnection()) {
      // dave's row ships with a fixed, published plaintext password ("passW0rD"). It is
      // overwritten with a fresh random value before it is ever read back, so the shipped
      // default cannot be typed into this form and pass.
      String freshPassword = rotatePassword(connection);

      try (Statement statement =
          connection.createStatement(
              ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY)) {
        ResultSet results =
            statement.executeQuery("SELECT password FROM user_system_data WHERE user_name = 'dave'");
        return (results != null && results.first()) ? results.getString("password") : freshPassword;
      }
    } catch (SQLException sqle) {
      log(sqle);
      return randomFallback();
    }
  }

  private String rotatePassword(Connection connection) {
    String freshPassword = randomFallback();
    try (var statement =
        connection.prepareStatement("UPDATE user_system_data SET password = ? WHERE user_name = ?")) {
      statement.setString(1, freshPassword);
      statement.setString(2, DAVE_USERNAME);
      statement.executeUpdate();
    } catch (SQLException sqle) {
      log(sqle);
    }
    return freshPassword;
  }

  private void log(SQLException sqle) {
    // deliberately swallowed: a failed rotation must not surface database internals to the
    // caller, the endpoint simply falls back to an unguessable value
  }

  private static String randomFallback() {
    return Long.toHexString(RANDOM.nextLong()) + Long.toHexString(RANDOM.nextLong());
  }
}
