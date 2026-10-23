#!/usr/bin/env bash
# Source to use the same cached Kotlin 2.0.21 compiler/runtime as the Gradle build.
FG_MAVEN_CACHE="${FG_MAVEN_CACHE:-$HOME/.gradle/caches/modules-2/files-2.1}"
fg_jar() {
    local result
    result=$(find "$FG_MAVEN_CACHE/$1/$2/$3" -name '*.jar' -type f -print -quit)
    [[ -n "$result" ]] || { echo "Missing cached $1:$2:$3" >&2; return 1; }
    printf '%s' "$result"
}
FG_STDLIB=$(fg_jar org.jetbrains.kotlin kotlin-stdlib 2.0.21)
FG_COMPILER_CP="$FG_STDLIB"
for coordinate in \
    'org.jetbrains.kotlin kotlin-compiler-embeddable 2.0.21' \
    'org.jetbrains.kotlin kotlin-script-runtime 2.0.21' \
    'org.jetbrains.kotlin kotlin-reflect 1.6.10' \
    'org.jetbrains.kotlin kotlin-daemon-embeddable 2.0.21' \
    'org.jetbrains.intellij.deps trove4j 1.0.20200330' \
    'org.jetbrains.kotlinx kotlinx-coroutines-core-jvm 1.6.4' \
    'org.jetbrains annotations 13.0'; do
    read -r group artifact version <<< "$coordinate"
    FG_COMPILER_CP="$FG_COMPILER_CP:$(fg_jar "$group" "$artifact" "$version")"
done
fg_kotlinc() { java -cp "$FG_COMPILER_CP" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler -no-stdlib -no-reflect "$@"; }
