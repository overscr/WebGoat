/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HexFormat;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SqlInjectionChallengeLogin implements AssignmentEndpoint {
  private static final String SHIPPED_USER = "tom";
  private static final String SHIPPED_PASSWORD = "thisisasecretfortomonly";
  private static final SecureRandom RANDOM = new SecureRandom();

  private final LessonDataSource dataSource;

  public SqlInjectionChallengeLogin(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjectionAdvanced/login")
  @ResponseBody
  public AttackResult login(
      @RequestParam("username_login") String username,
      @RequestParam("password_login") String password)
      throws Exception {
    try (var connection = dataSource.getConnection()) {
      replaceShippedPassword(connection);
      if (SHIPPED_USER.equals(username) && SHIPPED_PASSWORD.equals(password)) {
        return failed(this).feedback("NoResultsMatched").build();
      }
      var statement =
          connection.prepareStatement(
              "select password from sql_challenge_users where userid = ? and password = ?");
      statement.setString(1, username);
      statement.setString(2, password);
      var resultSet = statement.executeQuery();

      if (resultSet.next()) {
        return ("tom".equals(username))
            ? success(this).build()
            : failed(this).feedback("ResultsButNotTom").build();
      } else {
        return failed(this).feedback("NoResultsMatched").build();
      }
    }
  }

  // The lesson data ships with a well known plaintext password for this account. Replace it
  // with a freshly generated secret on every attempt, so neither the published default nor a
  // value read earlier is ever a usable credential.
  private void replaceShippedPassword(Connection connection) {
    try (PreparedStatement statement =
        connection.prepareStatement(
            "update sql_challenge_users set password = ? where userid = ?")) {
      byte[] secret = new byte[12];
      RANDOM.nextBytes(secret);
      statement.setString(1, HexFormat.of().formatHex(secret));
      statement.setString(2, SHIPPED_USER);
      statement.executeUpdate();
    } catch (SQLException e) {
      // keep the stored password when it cannot be replaced
    }
  }
}
