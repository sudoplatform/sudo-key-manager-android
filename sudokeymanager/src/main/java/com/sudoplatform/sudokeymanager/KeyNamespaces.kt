/*
 * Copyright © 2026 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager

/** Selects the internal constructors that create a store or key manager with no namespace, for [LegacyKeyManager]. */
internal object NoNamespace

/** Key namespace rules shared by the stores, the key managers and the archive. */
internal object KeyNamespaces {
    /** The namespace reported by a store or key manager with no namespace. */
    const val NONE = ""

    /** Returns [namespace] if it can be used as a key namespace. */
    fun requireValid(namespace: String): String {
        require(namespace.isNotEmpty()) { "A key namespace can't be empty." }
        return namespace
    }

    /** Thrown by operations that would reach other namespaces' keys from a store or key manager with no namespace. */
    fun unsupportedWithoutNamespace(operation: String): UnsupportedOperationException =
        UnsupportedOperationException(
            "$operation isn't supported without a key namespace, because it would reach every namespace's keys.",
        )
}
