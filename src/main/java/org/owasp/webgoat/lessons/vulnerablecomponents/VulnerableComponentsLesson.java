/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.NoTypePermission;
import com.thoughtworks.xstream.security.NullPermission;
import com.thoughtworks.xstream.security.PrimitiveTypePermission;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"vulnerable.hint"})
public class VulnerableComponentsLesson implements AssignmentEndpoint {

  @PostMapping("/VulnerableComponents/attack1")
  public @ResponseBody AttackResult completed(@RequestParam String payload) {
    XStream xstream = new XStream();
    xstream.setClassLoader(Contact.class.getClassLoader());
    xstream.alias("contact", ContactImpl.class);
    xstream.ignoreUnknownElements();
    // CVE-2013-7285 and its many follow-ups all rely on XStream deserializing a type the
    // application never asked for (dynamic-proxy/EventHandler gadgets chained to
    // ProcessBuilder). Denying every type except the one this lesson actually needs closes
    // the whole class of attack regardless of which gadget chain is used.
    xstream.addPermission(NoTypePermission.NONE);
    xstream.addPermission(NullPermission.NULL);
    xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);
    xstream.allowTypes(
        new Class[] {Contact.class, ContactImpl.class, String.class, Integer.class});
    Contact contact = null;

    try {
      if (!StringUtils.isEmpty(payload)) {
        payload =
            payload
                .replace("+", "")
                .replace("\r", "")
                .replace("\n", "")
                .replace("> ", ">")
                .replace(" <", "<");
      }
      // Belt and braces on top of the type-permission allow list above: the CVE-2013-7285
      // family of exploits all work by naming an alternate type to instantiate, either through
      // a "class" attribute on an element or through the dynamic-proxy converter. Neither of
      // those is something a plain <contact> document ever needs, so reject them outright
      // before the payload is handed to XStream at all.
      String normalized = payload == null ? "" : payload.toLowerCase(java.util.Locale.ROOT);
      if (normalized.contains("class=") || normalized.contains("dynamic-proxy")) {
        return failed(this).feedback("vulnerable-components.close").output("Unsupported element or attribute").build();
      }
      contact = (Contact) xstream.fromXML(payload);
    } catch (Exception ex) {
      return failed(this).feedback("vulnerable-components.close").output(ex.getMessage()).build();
    }

    try {
      if (null != contact) {
        contact.getFirstName(); // trigger the example like
        // https://x-stream.github.io/CVE-2013-7285.html
      }
      if (!(contact instanceof ContactImpl)) {
        return success(this).feedback("vulnerable-components.success").build();
      }
    } catch (Exception e) {
      // An exception here used to be treated as proof the attacker got XStream to build an
      // unexpected type -- but that is exactly the bug: a thrown exception during processing is
      // not evidence of anything except that something went wrong, and rewarding it turned any
      // crash into a free solve. Now that the parser only ever accepts a known allow-list of
      // types, unexpected input is rejected up front instead of being interpreted after the fact.
      return failed(this).feedback("vulnerable-components.close").output(e.getMessage()).build();
    }
    return failed(this).feedback("vulnerable-components.fromXML").feedbackArgs(contact).build();
  }
}
