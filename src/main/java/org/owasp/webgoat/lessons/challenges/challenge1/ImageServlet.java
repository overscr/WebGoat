/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge1;

import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

import java.io.IOException;
import java.security.SecureRandom;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ImageServlet {

  // Unpredictable and, unlike the old build, never written into a byte range of a public image.
  public static final int PINCODE = new SecureRandom().nextInt(9000) + 1000;

  @RequestMapping(
      method = {GET, POST},
      value = "/challenge/logo",
      produces = MediaType.IMAGE_PNG_VALUE)
  @ResponseBody
  public byte[] logo() throws IOException {
    // The pincode used to be stamped into four bytes of this same file, so anyone who requested
    // the logo could read the admin pincode straight out of the response body. The image is
    // served untouched now; PINCODE lives only in server memory.
    return new ClassPathResource("lessons/challenges/images/webgoat2.png")
        .getInputStream()
        .readAllBytes();
  }
}
