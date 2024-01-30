/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager

/**
 * Components of a key generated from a password or extracted from a key store.
 */
data class KeyComponents(
    /** Key data.  */
    var key: ByteArray = ByteArray(0),

    /** Salt used during the key generation.  */
    var salt: ByteArray = ByteArray(0),

    /** Number of pseudo-random rounds used during the key generation.  */
    @JvmField
    var rounds: Int = 0,

    /** Key name (aka alias)  */
    var name: String = "",
    var keyType: KeyType = KeyType.SYMMETRIC_KEY,
) {
    override fun toString(): String {
        val clz = this@KeyComponents.javaClass.simpleName
        return "$clz[key.size=${key.size} salt.size=${salt.size} rounds=$rounds name=$name keyType=$keyType"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as KeyComponents

        if (!key.contentEquals(other.key)) return false
        if (!salt.contentEquals(other.salt)) return false
        if (rounds != other.rounds) return false
        if (name != other.name) return false
        if (keyType != other.keyType) return false

        return true
    }

    override fun hashCode(): Int {
        var result = key.contentHashCode()
        result = 31 * result + salt.contentHashCode()
        result = 31 * result + rounds.hashCode()
        result = 31 * result + name.hashCode()
        result = 31 * result + keyType.hashCode()

        return result
    }
}
