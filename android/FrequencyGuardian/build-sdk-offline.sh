#!/usr/bin/env bash
# Fallback for environments where Gradle's local IPC sockets are prohibited.
# Builds the same source using installed Android SDK tools; no downloads.
set -euo pipefail
cd "$(dirname "$0")"
SDK="${ANDROID_SDK_ROOT:-/opt/android-sdk}"
TOOLS="${FG_BUILD_TOOLS:-$SDK/build-tools/35.0.0}"
source ./cached-kotlin.sh
OUT="$PWD/app/build/sdk-offline"
rm -rf "$OUT/classes" "$OUT/gen" "$OUT/dex"
mkdir -p "$OUT" "$OUT/gen" "$OUT/classes" "$OUT/dex"
"$TOOLS/aapt2" compile --dir app/src/main/res -o "$OUT/resources.zip"
# Manifest placeholders are normally resolved by AGP.
sed -e 's/${applicationId}/dev.frequency.guardian/g' -e 's/<manifest /<manifest package="dev.frequency.guardian" /' -e 's/<application /<application android:debuggable="true" /' app/src/main/AndroidManifest.xml > "$OUT/AndroidManifest.xml"
"$TOOLS/aapt2" link -o "$OUT/resources.apk" -I "$SDK/platforms/android-35/android.jar" --manifest "$OUT/AndroidManifest.xml" --java "$OUT/gen" --min-sdk-version 30 --target-sdk-version 35 --version-code 3 --version-name 0.3.0 "$OUT/resources.zip"
mkdir -p "$OUT/gen/dev/frequency/guardian"
printf 'package dev.frequency.guardian; public final class BuildConfig { public static final String VERSION_NAME="0.3.0"; }\n' > "$OUT/gen/dev/frequency/guardian/BuildConfig.java"
javac -source 17 -target 17 -classpath "$SDK/platforms/android-35/android.jar" -d "$OUT/classes" $(find "$OUT/gen" -name '*.java')
fg_kotlinc app/src/main/java/dev/frequency/guardian/*.kt -jvm-target 17 -classpath "$SDK/platforms/android-35/android.jar:$OUT/classes:$FG_STDLIB" -d "$OUT/classes"
jar cf "$OUT/classes.jar" -C "$OUT/classes" .
"$TOOLS/d8" --min-api 30 --lib "$SDK/platforms/android-35/android.jar" --output "$OUT/dex" "$OUT/classes.jar" "$FG_STDLIB"
cp "$OUT/resources.apk" "$OUT/unsigned.apk"
(cd "$OUT/dex" && zip -q -u "$OUT/unsigned.apk" classes*.dex)
"$TOOLS/zipalign" -f -p 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
# Disposable APK debug certificate only; NEVER the device approval identity.
if [[ ! -f "$OUT/debug.keystore" ]]; then
    keytool -genkeypair -keystore "$OUT/debug.keystore" -storepass android -keypass android -alias androiddebugkey -dname 'CN=Android Debug,O=Android,C=US' -keyalg RSA -keysize 2048 -validity 3650 >/dev/null 2>&1
fi
"$TOOLS/apksigner" sign --ks "$OUT/debug.keystore" --ks-pass pass:android --key-pass pass:android --out "$OUT/FrequencyGuardian-0.3.0-debug.apk" "$OUT/aligned.apk"
"$TOOLS/apksigner" verify --verbose "$OUT/FrequencyGuardian-0.3.0-debug.apk"
sha256sum "$OUT/FrequencyGuardian-0.3.0-debug.apk"
