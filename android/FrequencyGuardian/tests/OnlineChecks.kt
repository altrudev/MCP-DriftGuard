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

    val first = SavedDelivery("signed first decision", "first nonce")
    val empty = SavedDelivery(null, null)
    check(first.canDiscard(first.copy(), busy = false))
    check(!first.canDiscard(first, busy = true))
    // Open discard, confirm the first delivery, then save another decision before tapping discard.
    check(!first.canDiscard(empty, busy = false))
    val next = SavedDelivery("signed next decision", "next nonce")
    check(!first.canDiscard(next, busy = false))
    check(next.canDiscard(next.copy(), busy = false))
    check(!first.canDiscard(first.copy(receipt = "different receipt"), busy = false))
    check(!first.canDiscard(first.copy(nonce = "different nonce"), busy = false))
    check(!empty.canDiscard(empty, busy = false))
    check(!SavedDelivery("receipt", null).canDiscard(SavedDelivery("receipt", null), busy = false))
    println("PASS: discard confirmation binds the saved receipt and nonce; stale and active delivery refused (9 cases)")
}
