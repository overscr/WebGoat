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
      "SqlOnlyInputValidationOnKeywords-1",
      "SqlOnlyInputValidationOnKeywords-2",
      "SqlOnlyInputValidationOnKeywords-3"
    })
public class SqlOnlyInputValidationOnKeywords implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlOnlyInputValidationOnKeywords(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlOnlyInputValidationOnKeywords/attack")
  @ResponseBody
  public AttackResult attack(
      @RequestParam("userid_sql_only_input_validation_on_keywords") String userId) {
    // Stripping the SELECT/FROM keywords is a denylist, and denylists are brittle - a payload
    // that never needs those words (or spells them with a comment in the middle) sails through.
    // What actually stops injection here is that the value below is bound as a parameter, so
    // whatever text survives the filter is compared as data, never parsed as SQL.
    String sanitized = userId.toUpperCase().replace("FROM", "").replace("SELECT", "");
    if (sanitized.contains(" ")) {
      return failed(this).feedback("SqlOnlyInputValidationOnKeywords-failed").build();
    }

    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement("SELECT * FROM user_data WHERE last_name = ?")) {
      statement.setString(1, sanitized);
      try (ResultSet results = statement.executeQuery()) {
        return failed(this).output(renderAsHtml(results)).build();
      }
    } catch (SQLException e) {
      return failed(this).output(e.getMessage()).build();
    }
  }

  private String renderAsHtml(ResultSet results) throws SQLException {
    ResultSetMetaData metaData = results.getMetaData();
    int columnCount = metaData.getColumnCount();

    StringBuilder html = new StringBuilder("<p>");
    int rowCount = 0;
    while (results.next()) {
      if (rowCount == 0) {
        appendRow(html, i -> columnLabel(metaData, i), columnCount);
      }
      appendRow(html, i -> cellValue(results, i), columnCount);
      rowCount++;
    }

    if (rowCount == 0) {
      html.append("No results matched. Try Again.");
    }
    return html.append("</p>").toString();
  }

  private void appendRow(StringBuilder html, java.util.function.IntFunction<String> cell, int columnCount) {
    for (int i = 1; i <= columnCount; i++) {
      html.append(cell.apply(i)).append(", ");
    }
    html.append("<br />");
  }

  private String columnLabel(ResultSetMetaData metaData, int index) {
    try {
      return metaData.getColumnName(index);
    } catch (SQLException e) {
      return "";
    }
  }

  private String cellValue(ResultSet results, int index) {
    try {
      return results.getString(index);
    } catch (SQLException e) {
      return "";
    }
  }
}
