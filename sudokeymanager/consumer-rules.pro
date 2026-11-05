# Rules applied to apps that use this library.

# Gson converts key archives to and from JSON by reflection, so the archive classes keep their
# fields, constructors and generic signatures whatever the app's own rules are.
-keepattributes Signature,RuntimeVisibleAnnotations
-keep class com.sudoplatform.sudokeymanager.SecureKeyArchive$KeyArchive { <init>(); <fields>; }
-keep class com.sudoplatform.sudokeymanager.SecureKeyArchive$KeyInfo { <init>(); <fields>; }
-keep,allowobfuscation class com.sudoplatform.sudokeymanager.** extends com.google.gson.reflect.TypeToken
