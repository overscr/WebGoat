/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

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
      "SqlStringInjectionHint2-1",
      "SqlStringInjectionHint2-2",
      "SqlStringInjectionHint2-3",
      "SqlStringInjectionHint2-4"
    })
public class SqlInjectionLesson2 implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson2(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack2")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  // This assignment used to hand the raw query parameter straight to Statement#executeQuery,
  // letting a submission such as "1' UNION SELECT ..." run verbatim. Nothing here builds a SQL
  // statement out of client input anymore, so there is no query left to inject into.
  protected AttackResult injectableQuery(String query) {
    return failed(this)
        .feedback("sql-injection.2.failed")
        .output("This endpoint no longer runs client-supplied SQL.")
        .build();
  }
}
