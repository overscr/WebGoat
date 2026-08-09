/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cia;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpSession;
import java.util.Arrays;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CIAQuiz implements AssignmentEndpoint {

  private static final String SCORECARD_ATTRIBUTE = "cia.quiz.scorecard";

  private final String[] solutions = {"Solution 3", "Solution 1", "Solution 4", "Solution 2"};

  @PostMapping("/cia/quiz")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String[] question_0_solution,
      @RequestParam String[] question_1_solution,
      @RequestParam String[] question_2_solution,
      @RequestParam String[] question_3_solution,
      HttpSession session) {
    int correctAnswers = 0;
    boolean[] guesses = new boolean[solutions.length];

    String[] givenAnswers = {
      question_0_solution[0], question_1_solution[0], question_2_solution[0], question_3_solution[0]
    };

    for (int i = 0; i < solutions.length; i++) {
      if (givenAnswers[i].contains(solutions[i])) {
        // answer correct
        correctAnswers++;
        guesses[i] = true;
      } else {
        // answer incorrect
        guesses[i] = false;
      }
    }

    session.setAttribute(SCORECARD_ATTRIBUTE, guesses);

    if (correctAnswers == solutions.length) {
      return success(this).build();
    } else {
      return failed(this).build();
    }
  }

  @GetMapping("/cia/quiz")
  @ResponseBody
  public boolean[] getResults(HttpSession session) {
    Object scorecard = session.getAttribute(SCORECARD_ATTRIBUTE);
    if (scorecard instanceof boolean[] submitted) {
      return Arrays.copyOf(submitted, submitted.length);
    }
    return new boolean[solutions.length];
  }
}
