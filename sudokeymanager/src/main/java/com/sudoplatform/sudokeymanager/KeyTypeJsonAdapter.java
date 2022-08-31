/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import java.io.IOException;
import java.util.Locale;

/**
 * A Gson adapter that converts a {@link KeyType} to and from JSON. Used in serialisation
 * of the {@link SecureKeyArchive} and possibly elsewhere.
 */
public final class KeyTypeJsonAdapter extends TypeAdapter<KeyType> {

    @Override
    public void write(JsonWriter out, KeyType value) throws IOException {
        out.jsonValue(value.name());
    }

    @Override
    public KeyType read(JsonReader in) throws IOException {
        String value = in.nextString();
        switch (value.toLowerCase(Locale.ENGLISH)) {
            case "password":
                return KeyType.PASSWORD;
            case "publickey":
            case "public_key":
                return KeyType.PUBLIC_KEY;
            case "privatekey":
            case "private_key":
                return KeyType.PRIVATE_KEY;
            case "symmetrickey":
            case "symmetric_key":
                return KeyType.SYMMETRIC_KEY;
            default:
                break;
        }
        return null;
    }
}
