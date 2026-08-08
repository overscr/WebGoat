/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.jsonwebtoken.impl.TextCodec;
import java.security.SecureRandom;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "jwt-kid-hint1",
  "jwt-kid-hint2",
  "jwt-kid-hint3",
  "jwt-kid-hint4",
  "jwt-kid-hint5",
  "jwt-kid-hint6"
})
@RequestMapping("/JWT/")
public class JWTHeaderKIDEndpoint implements AssignmentEndpoint {

  /** The only key identifier this endpoint will ever verify a signature against. */
  private static final String EXPECTED_KID = "webgoat_key";

  /**
   * The key the lesson seeds into the database ("qwertyqwerty1234") lives in plain text in the
   * migration SQL, so anyone reading the source already knows it -- requiring a valid signature
   * does not help if the key itself is public. The stored value is rotated to one from
   * SecureRandom the first time it is needed, keeping the lookup mechanism identical while making
   * the actual key unguessable.
   */
  private static final String ROTATED_KEY = generateKey();

  private static String generateKey() {
    var key = new byte[24];
    new SecureRandom().nextBytes(key);
    return TextCodec.BASE64.encode(key);
  }

  private final LessonDataSource dataSource;

  private JWTHeaderKIDEndpoint(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("kid/follow/{user}")
  public @ResponseBody String follow(@PathVariable("user") String user) {
    if ("Jerry".equals(user)) {
      return "Following yourself seems redundant";
    } else {
      return "You are now following Tom";
    }
  }

  @PostMapping("kid/delete")
  public @ResponseBody AttackResult resetVotes(@RequestParam("token") String token) {
    if (StringUtils.isEmpty(token)) {
      return failed(this).feedback("jwt-invalid-token").build();
    } else {
      rotateStoredKeyIfNeeded();
      try {
        final String[] errorMessage = {null};
        Jwt jwt =
            Jwts.parser()
                .setSigningKeyResolver(
                    new SigningKeyResolverAdapter() {
                      @Override
                      public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
                        final String kid = (String) header.get("kid");
                        // The kid comes straight out of the token header, so it cannot be trusted
                        // to pick which row of jwt_keys gets used -- that allowed both SQL
                        // injection through the id lookup and "key confusion" (pointing the
                        // verifier at a different, weaker key). Only this application's own
                        // fixed key id is ever accepted; anything else is rejected up front.
                        if (!EXPECTED_KID.equals(kid)) {
                          return null;
                        }
                        try (var connection = dataSource.getConnection();
                            var statement =
                                connection.prepareStatement(
                                    "SELECT key FROM jwt_keys WHERE id = ?")) {
                          statement.setString(1, EXPECTED_KID);
                          try (ResultSet rs = statement.executeQuery()) {
                            while (rs.next()) {
                              return TextCodec.BASE64.decode(rs.getString(1));
                            }
                          }
                        } catch (SQLException e) {
                          errorMessage[0] = e.getMessage();
                        }
                        return null;
                      }
                    })
                .parseClaimsJws(token);
        if (errorMessage[0] != null) {
          return failed(this).output(errorMessage[0]).build();
        }
        Claims claims = (Claims) jwt.getBody();
        String username = (String) claims.get("username");
        if ("Jerry".equals(username)) {
          return failed(this).feedback("jwt-final-jerry-account").build();
        }
        if ("Tom".equals(username)) {
          return success(this).build();
        } else {
          return failed(this).feedback("jwt-final-not-tom").build();
        }
      } catch (JwtException e) {
        return failed(this).feedback("jwt-invalid-token").output(e.toString()).build();
      }
    }
  }

  /**
   * Replaces the seeded, publicly known key with the random one generated above. Scoped to the
   * exact seeded value so it is a no-op once the swap has already happened for this database.
   */
  private void rotateStoredKeyIfNeeded() {
    try (var connection = dataSource.getConnection();
        var statement =
            connection.prepareStatement("UPDATE jwt_keys SET key = ? WHERE id = ? AND key = ?")) {
      statement.setString(1, ROTATED_KEY);
      statement.setString(2, EXPECTED_KID);
      statement.setString(3, "qwertyqwerty1234");
      statement.executeUpdate();
    } catch (SQLException ignored) {
      // best effort -- the resolver above only ever trusts the fixed key id regardless
    }
  }
}
