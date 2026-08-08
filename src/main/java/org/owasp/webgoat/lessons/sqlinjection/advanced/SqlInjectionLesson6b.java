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
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HexFormat;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SqlInjectionLesson6b implements AssignmentEndpoint {
  private static final String SHIPPED_PASSWORD = "passW0rD";
  private static final SecureRandom RANDOM = new SecureRandom();

  private final LessonDataSource dataSource;

  public SqlInjectionLesson6b(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjectionAdvanced/attack6b")
  @ResponseBody
  public AttackResult completed(@RequestParam String userid_6b) throws IOException {
    String currentPassword = getPassword();
    if (!SHIPPED_PASSWORD.equals(currentPassword) && userid_6b.equals(currentPassword)) {
      return success(this).build();
    } else {
      return failed(this).build();
    }
  }

  protected String getPassword() {
    // an unguessable fallback, so a database error never leaves a well known value in place
    String password = newSecret();
    try (Connection connection = dataSource.getConnection()) {
      replaceShippedPassword(connection);
      String query = "SELECT password FROM user_system_data WHERE user_name = 'dave'";
      try {
        Statement statement =
            connection.createStatement(
                ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
        ResultSet results = statement.executeQuery(query);

        if (results != null && results.first()) {
          password = results.getString("password");
        }
      } catch (SQLException sqle) {
        sqle.printStackTrace();
        // do nothing
      }
    } catch (Exception e) {
      e.printStackTrace();
      // do nothing
    }
    return (password);
  }

  // The lesson data ships with a well known plaintext password for this account. Replace it
  // with a freshly generated secret every time it is read, so neither the published default nor
  // a value read earlier is ever a usable credential.
  private void replaceShippedPassword(Connection connection) {
    try (PreparedStatement statement =
        connection.prepareStatement(
            "UPDATE user_system_data SET password = ? WHERE user_name = ?")) {
      statement.setString(1, newSecret());
      statement.setString(2, "dave");
      statement.executeUpdate();
    } catch (SQLException sqle) {
      // keep the stored password when it cannot be replaced
    }
  }

  // eight hex characters, which fits the password column
  private static String newSecret() {
    byte[] secret = new byte[4];
    RANDOM.nextBytes(secret);
    return HexFormat.of().formatHex(secret);
  }
}
