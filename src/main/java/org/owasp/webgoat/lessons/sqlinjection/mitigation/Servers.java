/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.LessonDataSource;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author nbaars
 * @since 6/13/17.
 */
@RestController
@RequestMapping("SqlInjectionMitigations/servers")
@Slf4j
public class Servers {

  /**
   * An ORDER BY target is an identifier, not a value, so it can never be supplied as a bind
   * parameter. The only safe construction is to map the request onto a fixed set of known columns
   * and to build the statement from the matched constant rather than from the request text.
   */
  private static final Set<String> SORTABLE_COLUMNS =
      Set.of("id", "hostname", "ip", "mac", "status", "description");

  private final LessonDataSource dataSource;

  @AllArgsConstructor
  @Getter
  private class Server {

    private String id;
    private String hostname;
    private String ip;
    private String mac;
    private String status;
    private String description;
  }

  public Servers(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public List<Server> sort(@RequestParam String column) throws Exception {
    List<Server> servers = new ArrayList<>();
    String orderBy = resolveSortColumn(column);

    try (var connection = dataSource.getConnection()) {
      try (var statement =
          connection.prepareStatement(
              "select id, hostname, ip, mac, status, description from SERVERS where status <> 'out"
                  + " of order' order by "
                  + orderBy)) {
        try (var rs = statement.executeQuery()) {
          while (rs.next()) {
            Server server =
                new Server(
                    rs.getString(1),
                    rs.getString(2),
                    rs.getString(3),
                    rs.getString(4),
                    rs.getString(5),
                    rs.getString(6));
            servers.add(server);
          }
        }
      }
    }
    return servers;
  }

  private static String resolveSortColumn(String requested) {
    if (requested == null) {
      return "id";
    }
    String candidate = requested.trim().toLowerCase(Locale.ROOT);
    // Anything the table does not actually have — including a nested CASE expression used to
    // ask the database yes/no questions — falls back to the default ordering instead of being
    // concatenated into the statement.
    return SORTABLE_COLUMNS.contains(candidate) ? candidate : "id";
  }
}
