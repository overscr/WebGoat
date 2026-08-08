/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss.stored;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.springframework.http.MediaType.ALL_VALUE;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.xss.Comment;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
public class StoredXssComments implements AssignmentEndpoint {

  private static final DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd, HH:mm:ss");

  private static final int MAX_COMMENT_LENGTH = 2000;

  private static final Map<String, List<Comment>> userComments = new HashMap<>();
  private static final List<Comment> comments = new ArrayList<>();

  static {
    comments.add(
        new Comment(
            "secUriTy",
            LocalDateTime.now().format(fmt),
            HtmlUtils.htmlEscape(
                "<script>console.warn('unit test me')</script>Comment for Unit Testing")));
    comments.add(new Comment("webgoat", LocalDateTime.now().format(fmt), "This comment is safe"));
    comments.add(new Comment("guest", LocalDateTime.now().format(fmt), "This one is safe too."));
    comments.add(
        new Comment(
            "guest",
            LocalDateTime.now().format(fmt),
            "Can you post a comment, calling webgoat.customjs.phoneHome() ?"));
  }

  @GetMapping(
      path = "/CrossSiteScriptingStored/stored-xss",
      produces = MediaType.APPLICATION_JSON_VALUE,
      consumes = ALL_VALUE)
  @ResponseBody
  public Collection<Comment> retrieveComments(@CurrentUsername String username) {
    List<Comment> allComments = Lists.newArrayList();
    Collection<Comment> newComments = userComments.get(username);
    allComments.addAll(comments);
    if (newComments != null) {
      allComments.addAll(newComments);
    }
    Collections.reverse(allComments);
    return allComments;
  }

  @PostMapping("/CrossSiteScriptingStored/stored-xss")
  @ResponseBody
  public AttackResult createNewComment(
      @RequestBody String commentStr, @CurrentUsername String username) {
    Comment comment = parseJson(commentStr);

    // Comments are persisted and later rendered into the page for every other reader, so the
    // body is encoded on the way in. Whatever markup the author types is stored — and shown —
    // as text, which is what stops one visitor's comment from scripting the next one's browser.
    String text = comment.getText();
    if (text == null || text.length() > MAX_COMMENT_LENGTH) {
      return failed(this).feedback("xss-stored-comment-failure").build();
    }
    comment.setText(HtmlUtils.htmlEscape(text));

    List<Comment> comments = userComments.getOrDefault(username, new ArrayList<>());
    comment.setDateTime(LocalDateTime.now().format(fmt));
    comment.setUser(username);

    comments.add(comment);
    userComments.put(username, comments);

    return failed(this).feedback("xss-stored-comment-failure").build();
  }

  private Comment parseJson(String comment) {
    ObjectMapper mapper = new ObjectMapper();
    try {
      return mapper.readValue(comment, Comment.class);
    } catch (IOException e) {
      return new Comment();
    }
  }
}
