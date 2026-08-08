/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.springframework.http.MediaType.ALL_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FilenameUtils;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@AssignmentHints({
  "path-traversal-zip-slip.hint1",
  "path-traversal-zip-slip.hint2",
  "path-traversal-zip-slip.hint3",
  "path-traversal-zip-slip.hint4"
})
@Slf4j
public class ProfileZipSlip extends ProfileUploadBase {

  public ProfileZipSlip(@Value("${webgoat.server.directory}") String webGoatHomeDirectory) {
    super(webGoatHomeDirectory);
  }

  @PostMapping(
      value = "/PathTraversal/zip-slip",
      consumes = ALL_VALUE,
      produces = APPLICATION_JSON_VALUE)
  @ResponseBody
  public AttackResult uploadFileHandler(
      @RequestParam("uploadedFileZipSlip") MultipartFile file, @CurrentUsername String username) {
    if (!file.getOriginalFilename().toLowerCase().endsWith(".zip")) {
      return failed(this).feedback("path-traversal-zip-slip.no-zip").build();
    } else {
      return processZipUpload(file, username);
    }
  }

  @SneakyThrows
  private AttackResult processZipUpload(MultipartFile file, String username) {
    var tmpZipDirectory = Files.createTempDirectory(username);
    cleanupAndCreateDirectoryForUser(username);
    var currentImage = getProfilePictureAsBase64(username);

    try {
      // Only the base name of the client-supplied filename is trusted for where the upload
      // itself lands; a name like "../../../etc/passwd" is reduced to "passwd" here.
      var safeUploadName = FilenameUtils.getName(file.getOriginalFilename());
      var uploadedZipFile = tmpZipDirectory.resolve(safeUploadName);
      FileCopyUtils.copy(file.getBytes(), uploadedZipFile.toFile());

      var extractionRoot = tmpZipDirectory.toFile().getCanonicalFile().toPath();
      ZipFile zip = new ZipFile(uploadedZipFile.toFile());
      Enumeration<? extends ZipEntry> entries = zip.entries();
      while (entries.hasMoreElements()) {
        ZipEntry entry = entries.nextElement();
        Path destination = resolveWithinRoot(extractionRoot, entry.getName());
        if (destination == null) {
          // A zip-slip entry: its name resolves outside the directory we are extracting into
          // (e.g. "../../etc/cron.d/evil"), so the archive is rejected instead of written.
          return failed(this).output("path-traversal-zip-slip.extracted").build();
        }
        try (InputStream entryStream = zip.getInputStream(entry)) {
          Files.copy(entryStream, destination, StandardCopyOption.REPLACE_EXISTING);
        }
      }

      return isSolved(currentImage, getProfilePictureAsBase64(username));
    } catch (IOException e) {
      return failed(this).output(e.getMessage()).build();
    }
  }

  /**
   * Resolves a zip entry name against the extraction root and returns the resulting path only if
   * it is still contained within that root once path traversal segments are collapsed. Returns
   * null for an entry that would land outside of it.
   */
  private Path resolveWithinRoot(Path extractionRoot, String entryName) throws IOException {
    Path candidate = new File(extractionRoot.toFile(), entryName).getCanonicalFile().toPath();
    return candidate.startsWith(extractionRoot) ? candidate : null;
  }

  private AttackResult isSolved(byte[] currentImage, byte[] newImage) {
    if (Arrays.equals(currentImage, newImage)) {
      return failed(this).output("path-traversal-zip-slip.extracted").build();
    }
    return success(this).output("path-traversal-zip-slip.extracted").build();
  }

  @GetMapping("/PathTraversal/zip-slip/")
  @ResponseBody
  public ResponseEntity<?> getProfilePicture(@CurrentUsername String username) {
    return super.getProfilePicture(username);
  }

  @GetMapping("/PathTraversal/zip-slip/profile-image/{username}")
  @ResponseBody
  public ResponseEntity<?> getProfileImage(@PathVariable String username) {
    return ResponseEntity.notFound().build();
  }
}
