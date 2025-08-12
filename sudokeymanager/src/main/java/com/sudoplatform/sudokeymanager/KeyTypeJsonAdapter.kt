/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager

import com.google.gson.TypeAdapter
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonWriter
import java.io.IOException

/**
 * A Gson adapter that converts a [KeyType] to and from JSON. Used in serialisation
 * of the [SecureKeyArchive] and possibly elsewhere.
 */
class KeyTypeJsonAdapter : TypeAdapter<KeyType?>() {
    @Throws(IOException::class)
    override fun write(
        out: JsonWriter,
        value: KeyType?,
    ) {
        out.jsonValue(value!!.name)
    }

    @Throws(IOException::class)
    override fun read(`in`: JsonReader): KeyType? {
        val value = `in`.nextString()
        when (value.lowercase()) {
            "password" -> return KeyType.PASSWORD
            "publickey", "public_key" -> return KeyType.PUBLIC_KEY
            "privatekey", "private_key" -> return KeyType.PRIVATE_KEY
            "symmetrickey", "symmetric_key" -> return KeyType.SYMMETRIC_KEY
            else -> {}
        }
        return null
    }
}
