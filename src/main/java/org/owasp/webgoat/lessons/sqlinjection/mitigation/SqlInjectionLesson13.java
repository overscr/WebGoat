/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint-mitigation-13-1",
      "SqlStringInjectionHint-mitigation-13-2",
      "SqlStringInjectionHint-mitigation-13-3",
      "SqlStringInjectionHint-mitigation-13-4"
    })
@Slf4j
public class SqlInjectionLesson13 implements AssignmentEndpoint {

  private static final String PROD_HOSTNAME = "webgoat-prd";

  private final LessonDataSource dataSource;

  public SqlInjectionLesson13(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjectionMitigations/attack12a")
  @ResponseBody
  public AttackResult completed(@RequestParam String ip) {
    // Retired servers are excluded from the overview page, so this lookup excludes them from the
    // WHERE clause too; otherwise a caller could confirm the ip of a server they were never
    // supposed to be able to see listed in the first place. ip and hostname both travel as bind
    // parameters, never as concatenated text.
    String query = "select ip from servers where ip = ? and hostname = ? and status <> 'out of order'";
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement = connection.prepareStatement(query)) {
      statement.setString(1, ip);
      statement.setString(2, PROD_HOSTNAME);
      try (ResultSet resultSet = statement.executeQuery()) {
        return resultSet.next() ? success(this).build() : failed(this).build();
      }
    } catch (SQLException e) {
      log.error("Failed", e);
      return failed(this).build();
    }
  }
}
