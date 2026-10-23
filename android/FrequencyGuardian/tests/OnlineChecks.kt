package dev.frequency.guardian

fun main() {
    check(OnlineProtocol.endpoint("https://approval.invalid:8443/") == "https://approval.invalid:8443")
    listOf("http://approval.invalid", "https://user:secret@approval.invalid", "https://approval.invalid/path", "https://approval.invalid?x=y", "https://approval.invalid#x", "https://approval.invalid:0", "https:///missing").forEach {
        check(runCatching { OnlineProtocol.endpoint(it) }.isFailure)
    }
    check(OnlineProtocol.token("a".repeat(43)).length == 43)
    listOf("", "a".repeat(42), "a".repeat(44), "\n" + "a".repeat(42)).forEach {
        check(runCatching { OnlineProtocol.token(it) }.isFailure)
    }
    println("PASS: online HTTPS origin and pairing token validation (13 cases)")
}
