/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.dummy.insecure.framework;

import java.io.ObjectInputStream;
import java.io.Serializable;
import java.time.LocalDateTime;
import lombok.extern.slf4j.Slf4j;

@Slf4j
// TODO move back to lesson
public class VulnerableTaskHolder implements Serializable {

  private static final long serialVersionUID = 2;

  private String taskName;
  private String taskAction;
  private LocalDateTime requestedExecutionTime;

  public VulnerableTaskHolder(String taskName, String taskAction) {
    super();
    this.taskName = taskName;
    this.taskAction = taskAction;
    this.requestedExecutionTime = LocalDateTime.now();
  }

  @Override
  public String toString() {
    return "VulnerableTaskHolder [taskName="
        + taskName
        + ", taskAction="
        + taskAction
        + ", requestedExecutionTime="
        + requestedExecutionTime
        + "]";
  }

  /**
   * Rehydrate a task from a stream. A deserialization hook is not a place to run commands: an
   * attacker who can craft the serialized bytes controls {@code taskAction} completely, and
   * shelling out to it here would hand them command execution. So this only ever repopulates
   * fields, it never launches a process for the caller.
   */
  private void readObject(ObjectInputStream stream) throws Exception {
    stream.defaultReadObject();

    log.info("deserialized task '{}' scheduled for {}", taskName, requestedExecutionTime);

    LocalDateTime now = LocalDateTime.now();
    boolean expired =
        requestedExecutionTime == null
            || requestedExecutionTime.isBefore(now.minusMinutes(10))
            || requestedExecutionTime.isAfter(now);
    if (expired) {
      log.debug(this.toString());
      throw new IllegalArgumentException("outdated");
    }

    // taskAction is untrusted attacker-controlled content: it is logged for visibility and
    // nothing else touches it, in particular it is never handed to a shell or process builder.
    log.info("task action left unexecuted: {}", taskAction);
  }
}
