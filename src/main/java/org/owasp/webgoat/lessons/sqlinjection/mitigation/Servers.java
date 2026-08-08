/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.LessonDataSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * @author nbaars
 * @since 6/13/17.
 */
@RestController
@RequestMapping("SqlInjectionMitigations/servers")
@Slf4j
public class Servers {

  // JDBC has no way to bind an identifier (column name) as a parameter the way it binds a value,
  // so "order by " + column used to let the column parameter carry arbitrary SQL straight into
  // the statement. The only safe option is to check the requested name against a fixed allowlist
  // of the columns this table actually has before it is ever placed in the query text.
  private static final List<String> KNOWN_COLUMNS =
      List.of("id", "hostname", "ip", "mac", "status", "description");

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
    String sortColumn = column.toLowerCase(Locale.ROOT);
    if (!KNOWN_COLUMNS.contains(sortColumn)) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown sort column");
    }

    List<Server> servers = new ArrayList<>();
    try (var connection = dataSource.getConnection()) {
      try (var statement =
          connection.prepareStatement(
              "select id, hostname, ip, mac, status, description from SERVERS where status <> 'out"
                  + " of order' order by "
                  + sortColumn)) {
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
}
