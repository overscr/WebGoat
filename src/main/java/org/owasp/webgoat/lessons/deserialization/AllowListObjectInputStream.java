/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.deserialization;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Set;
import org.dummy.insecure.framework.VulnerableTaskHolder;

/**
 * An {@link ObjectInputStream} that will only resolve the classes it has been told to expect.
 *
 * <p>Deserializing an untrusted stream with the stock implementation lets the sender pick which
 * classes get instantiated, which is what turns a serialized blob into remote code execution by way
 * of a gadget chain. Naming the expected types up front removes that choice.
 */
class AllowListObjectInputStream extends ObjectInputStream {

  private static final Set<String> ALLOWED_CLASSES =
      Set.of(VulnerableTaskHolder.class.getName(), String.class.getName());

  AllowListObjectInputStream(InputStream in) throws IOException {
    super(in);
  }

  @Override
  protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
    if (!ALLOWED_CLASSES.contains(desc.getName())) {
      throw new InvalidClassException(desc.getName(), "Unexpected class in serialized data");
    }
    return super.resolveClass(desc);
  }

  @Override
  protected Class<?> resolveProxyClass(String[] interfaces) throws IOException, ClassNotFoundException {
    // Dynamic proxies are resolved through a separate code path that a class-name allow list
    // does not cover, so proxy-based gadget chains have to be rejected outright here too.
    throw new InvalidClassException("Dynamic proxies are not accepted");
  }
}
