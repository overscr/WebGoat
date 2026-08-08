/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.clientsidefiltering;

import jakarta.annotation.PostConstruct;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

@RestController
@Slf4j
public class Salaries {

  private static final String[] EXPOSED_FIELDS = {
    "UserID", "FirstName", "LastName", "SSN", "Salary"
  };

  @Value("${webgoat.user.directory}")
  private String webGoatHomeDirectory;

  @PostConstruct
  public void copyFiles() {
    ClassPathResource classPathResource = new ClassPathResource("lessons/employees.xml");
    File targetDirectory = new File(webGoatHomeDirectory, "/ClientSideFiltering");
    if (!targetDirectory.exists()) {
      targetDirectory.mkdir();
    }
    try {
      FileCopyUtils.copy(
          classPathResource.getInputStream(),
          new FileOutputStream(new File(targetDirectory, "employees.xml")));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @GetMapping("clientSideFiltering/salaries")
  @ResponseBody
  public List<Map<String, Object>> invoke(
      @RequestParam(value = "userId", required = false) String userId) {
    File d = new File(webGoatHomeDirectory, "ClientSideFiltering/employees.xml");
    List<Map<String, Object>> json = new ArrayList<>();

    // Every row used to be sent to the browser and left it to the page to only render the ones
    // the logged-in employee is allowed to see; anyone reading the raw response instead of the
    // rendered table could read a colleague's - or the CEO's - salary and SSN. The server now
    // only ever returns the records the caller is entitled to see: their own, and the records of
    // the people they manage.
    if (userId == null || userId.isBlank()) {
      return json;
    }

    XPathFactory factory = XPathFactory.newInstance();
    XPath path = factory.newXPath();

    try (InputStream is = new FileInputStream(d)) {
      InputSource inputSource = new InputSource(is);
      NodeList employees =
          (NodeList) path.evaluate("/Employees/Employee", inputSource, XPathConstants.NODESET);

      for (int i = 0; i < employees.getLength(); i++) {
        Node employee = employees.item(i);
        if (isEntitledToView(employee, userId)) {
          json.add(toJson(employee));
        }
      }
    } catch (XPathExpressionException e) {
      log.error("Unable to parse xml", e);
    } catch (IOException e) {
      log.error("Unable to read employees.xml at location: '{}'", d);
    }
    return json;
  }

  /** An employee record may be viewed by the employee themselves and by their managers. */
  private boolean isEntitledToView(Node employee, String requestingUserId) {
    if (requestingUserId.equals(fieldValue(employee, "UserID"))) {
      return true;
    }
    Node managersNode = child(employee, "Managers");
    if (managersNode == null) {
      return false;
    }
    NodeList managers = managersNode.getChildNodes();
    for (int i = 0; i < managers.getLength(); i++) {
      Node manager = managers.item(i);
      if ("Manager".equals(manager.getNodeName())
          && requestingUserId.equals(manager.getTextContent().trim())) {
        return true;
      }
    }
    return false;
  }

  private Map<String, Object> toJson(Node employee) {
    Map<String, Object> employeeJson = new HashMap<>();
    for (String field : EXPOSED_FIELDS) {
      employeeJson.put(field, fieldValue(employee, field));
    }
    return employeeJson;
  }

  private Node child(Node employee, String name) {
    NodeList children = employee.getChildNodes();
    for (int i = 0; i < children.getLength(); i++) {
      Node child = children.item(i);
      if (name.equals(child.getNodeName())) {
        return child;
      }
    }
    return null;
  }

  private String fieldValue(Node employee, String name) {
    Node field = child(employee, name);
    return field == null ? "" : field.getTextContent().trim();
  }
}
