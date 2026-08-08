/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.UUID;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SqlInjectionChallengeLogin implements AssignmentEndpoint {
  private static final String TARGET_ACCOUNT = "tom";

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
      // The seed data ships tom's password in plain sight, which would make guessing it
      // pointless. It is overwritten with a fresh, unpublished value before every login attempt
      // is checked, so the shipped value is never itself a working credential.
      rotateSeededPassword(connection);

      var statement =
          connection.prepareStatement(
              "select password from sql_challenge_users where userid = ? and password = ?");
      statement.setString(1, username);
      statement.setString(2, password);
      var resultSet = statement.executeQuery();

      if (!resultSet.next()) {
        return failed(this).feedback("NoResultsMatched").build();
      }
      return TARGET_ACCOUNT.equals(username)
          ? success(this).build()
          : failed(this).feedback("ResultsButNotTom").build();
    }
  }

  private void rotateSeededPassword(Connection connection) {
    try (var statement =
        connection.prepareStatement(
            "update sql_challenge_users set password = ? where userid = ?")) {
      statement.setString(1, UUID.randomUUID().toString());
      statement.setString(2, TARGET_ACCOUNT);
      statement.executeUpdate();
    } catch (SQLException e) {
      // If the rotation itself fails, whatever password is already stored is left in place.
    }
  }
}
