/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sudoplatform.sudokeymanager;

/**
 * Components of a key generated from a password or extracted from a key store.
 */
public class KeyComponents {

    /** Key data. */
    public byte[] key;

    /** Salt used during the key generation. */
    public byte[] salt;

    /** Number of pseudo-random rounds used during the key generation. */
    public int rounds;

    /** Key name (aka alias) */
    public String name;

    public KeyType keyType;
}
