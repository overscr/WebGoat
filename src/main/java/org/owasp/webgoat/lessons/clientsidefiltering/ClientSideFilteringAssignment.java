/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.clientsidefiltering;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.xml.sax.InputSource;

@RestController
@Slf4j
@AssignmentHints({
  "ClientSideFilteringHint1",
  "ClientSideFilteringHint2",
  "ClientSideFilteringHint3",
  "ClientSideFilteringHint4"
})
public class ClientSideFilteringAssignment implements AssignmentEndpoint {

  private static final String CEO_USER_ID = "112";

  @Value("${webgoat.user.directory}")
  private String webGoatHomeDirectory;

  @PostMapping("/clientSideFiltering/attack1")
  @ResponseBody
  public AttackResult completed(@RequestParam String answer) {
    // The expected answer used to be a literal in the source, which means reading the public
    // repository was enough to pass this assignment without ever looking at the leaked salary
    // data. The CEO's current salary is instead read from the same record store the salaries
    // endpoint serves, so only someone who actually retrieved that value can answer correctly.
    String ceoSalary = lookupCeoSalary();
    return ceoSalary != null && ceoSalary.equals(answer)
        ? success(this).feedback("assignment.solved").build()
        : failed(this).feedback("ClientSideFiltering.incorrect").build();
  }

  private String lookupCeoSalary() {
    File employeeRecords = new File(webGoatHomeDirectory, "ClientSideFiltering/employees.xml");
    XPath path = XPathFactory.newInstance().newXPath();
    try (InputStream is = new FileInputStream(employeeRecords)) {
      String expression =
          "/Employees/Employee[UserID='" + CEO_USER_ID + "']/Salary/text()";
      return (String) path.evaluate(expression, new InputSource(is), XPathConstants.STRING);
    } catch (XPathExpressionException e) {
      log.error("Unable to parse xml", e);
    } catch (IOException e) {
      log.error("Unable to read employees.xml at location: '{}'", employeeRecords);
    }
    return null;
  }
}
