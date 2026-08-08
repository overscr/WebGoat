/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.authbypass;

import java.util.HashMap;
import java.util.Map;

/** Created by appsec on 7/18/17. */
public class AccountVerificationHelper {

  // simulating database storage of verification credentials
  private static final Integer verifyUserId = 1223445;
  private static final Map<String, String> userSecQuestions = new HashMap<>();

  static {
    userSecQuestions.put("secQuestion0", "Dr. Watson");
    userSecQuestions.put("secQuestion1", "Baker Street");
  }

  private static final Map<Integer, Map> secQuestionStore = new HashMap<>();

  static {
    secQuestionStore.put(verifyUserId, userSecQuestions);
  }

  // end 'data store set up'

  // this is to aid feedback in the attack process and is not intended to be part of the
  // 'vulnerable' code
  public boolean didUserLikelylCheat(HashMap<String, String> submittedAnswers) {
    boolean likely = false;

    if (submittedAnswers.size() == secQuestionStore.get(verifyUserId).size()) {
      likely = true;
    }

    if ((submittedAnswers.containsKey("secQuestion0")
            && submittedAnswers
                .get("secQuestion0")
                .equals(secQuestionStore.get(verifyUserId).get("secQuestion0")))
        && (submittedAnswers.containsKey("secQuestion1")
            && submittedAnswers
                .get("secQuestion1")
                .equals(secQuestionStore.get(verifyUserId).get("secQuestion1")))) {
      likely = true;
    } else {
      likely = false;
    }

    return likely;
  }

  // end of cheating check ... the method below is the one of real interest. Can you find the flaw?

  public boolean verifyAccount(Integer userId, HashMap<String, String> submittedQuestions) {
    Map<String, String> expectedAnswers = secQuestionStore.get(verifyUserId);
    if (expectedAnswers == null) {
      return false;
    }

    // short circuit if the number of submitted answers does not match
    if (submittedQuestions.entrySet().size() != expectedAnswers.size()) {
      return false;
    }

    // Every expected question must actually be present and answered correctly. The previous
    // implementation only validated a question when the submitted map *contained* its key
    // (`containsKey(...) && ...`), so simply renaming/omitting the expected parameters (while
    // still submitting the right number of them) skipped every real check and fell through to
    // `return true`. Iterating over the known-good answers instead of the attacker-controlled
    // submission means a missing or renamed answer is always treated as incorrect.
    for (Map.Entry<String, String> expected : expectedAnswers.entrySet()) {
      String submittedAnswer = submittedQuestions.get(expected.getKey());
      if (submittedAnswer == null || !submittedAnswer.equals(expected.getValue())) {
        return false;
      }
    }

    // else
    return true;
  }
}
