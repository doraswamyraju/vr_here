# Preserve line numbers for Crashlytics stack traces
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# Keep Data Models & Network Serialized Classes
-keepclassmembers class com.sbr.vrherebms.data.model.** { *; }
-keep class com.sbr.vrherebms.data.model.** { *; }

# Retrofit & Gson
-keepattributes Signature, InnerClasses, EnclosingMethod
-keepattributes *Annotation*
-dontwarn retrofit2.**
-keep class retrofit2.** { *; }

# Razorpay SDK
-keep class com.razorpay.** { *; }
-dontwarn com.razorpay.**

# Firebase
-dontwarn com.google.firebase.**