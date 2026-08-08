/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
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
    value = {"SqlOnlyInputValidation-1", "SqlOnlyInputValidation-2", "SqlOnlyInputValidation-3"})
public class SqlOnlyInputValidation implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlOnlyInputValidation(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlOnlyInputValidation/attack")
  @ResponseBody
  public AttackResult attack(@RequestParam("userid_sql_only_input_validation") String userId) {
    // Rejecting whitespace alone is not a defense - "1'or'1'='1" contains none - it only breaks
    // the classic textbook payload. The actual protection is that last_name is bound below rather
    // than concatenated into the statement text.
    if (userId.contains(" ")) {
      return failed(this).feedback("SqlOnlyInputValidation-failed").build();
    }
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement("SELECT * FROM user_data WHERE last_name = ?")) {
      statement.setString(1, userId);
      try (ResultSet results = statement.executeQuery()) {
        return failed(this).output(renderRows(results)).build();
      }
    } catch (SQLException e) {
      return failed(this).output(e.getMessage()).build();
    }
  }

  private String renderRows(ResultSet results) throws SQLException {
    int columnCount = results.getMetaData().getColumnCount();
    List<String> lines = new ArrayList<>();
    lines.add(columnNames(results, columnCount));

    while (results.next()) {
      StringBuilder row = new StringBuilder();
      for (int col = 1; col <= columnCount; col++) {
        row.append(results.getString(col)).append(", ");
      }
      lines.add(row.toString());
    }

    if (lines.size() == 1) {
      return "<p>No results matched. Try Again.</p>";
    }
    return "<p>" + String.join("<br />", lines) + "</p>";
  }

  private String columnNames(ResultSet results, int columnCount) throws SQLException {
    ResultSetMetaData metaData = results.getMetaData();
    StringBuilder header = new StringBuilder();
    for (int col = 1; col <= columnCount; col++) {
      header.append(metaData.getColumnName(col)).append(", ");
    }
    return header.toString();
  }
}
