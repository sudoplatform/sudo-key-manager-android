# Sudo Key Manager Android SDK

## Overview

The Sudo Platform makes it seamless for developers to integrate Sudo capabilities into their existing applications with minimal effort. The Sudo Key Manager SDK is a library used by other Sudo Platform SDKs to perform cryptographic functions.

## Version Support

| Technology        | Supported version |
| ----------------- |-------------------|
| Minimum API Level | 26                |
| Kotlin version    | 2.1+              |

## Key namespaces

Every key manager has a namespace, which keeps its keys apart from those of other key managers in
the same app. Create one with `KeyManagerFactory(context).createAndroidKeyManager(namespace)`, or
`createAndroidKeyManager(namespace, databaseName)`. The namespace must not be empty.

- A key manager only lists, exports, archives and removes keys in its own namespace. Matching is
  exact and case-sensitive.
- `KeyManagerInterface.namespace` reports the namespace.
- Avoid dotted namespaces that extend another one, such as `tel` and `tel.sub`: removing all keys
  of `tel` also removes those of `tel.sub`.

### Key archives

- Every key in an archive carries the key manager's namespace as `NameSpace`.
- Importing an archive (`unarchive`, then `saveKeys`) keeps only keys whose `NameSpace` is the key
  manager's namespace. Keys with another `NameSpace`, an empty one or none are skipped.
- If an archive has no keys in the namespace, `unarchive` throws `SecureKeyArchiveException` with
  reason `NO_KEYS_FOR_NAMESPACE`, and no existing key is removed.
  `SecureKeyArchiveInterface.namespaces` lists the namespaces the archive holds.
- To move keys between platforms, give the key manager the same namespace on every platform.

### Keys stored with no namespace

Key manager 9.x and earlier could create a key manager with no namespace
(`createAndroidKeyManager()` with no arguments). That, and the store and `AndroidKeyManager`
constructors without a namespace, are removed.

To move keys stored that way into a namespace, use `KeyManagerFactory.createLegacyKeyManager()`.
It reads and deletes keys by name only. Read each key, add it to a namespaced key manager, then
delete it from the legacy key manager. The keys don't record which key manager stored them, so
nothing lists, exports or removes them in bulk.

## Questions and Support

File any issues you find on the project's GitHub repository. Be careful not to share any Personally Identifiable Information (PII) or sensitive account information (API keys, credentials, etc.) when reporting an issue.

For general inquiries related to the Sudo Platform, please contact [partners@sudoplatform.com](mailto:partners@sudoplatform.com)
