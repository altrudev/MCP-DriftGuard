package dev.frequency.guardian

import java.util.Base64
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom

/** Closed diagnostic type: external JSON/intents cannot construct an approval. */
internal class LocalFixture private constructor(
    private val nonceValue: ByteArray, val issued: Long, val expires: Long, private val actionValue: ByteArray
) {
    val nonce: ByteArray get() = nonceValue.copyOf()
    val action: ByteArray get() = actionValue.copyOf()
    private var consumed = false
    private val createdNanos = System.nanoTime()
    fun consume(now: Long): ByteArray {
        validate(now)
        consumed = true // Burn even if the subsequent signing operation fails.
        return bytes()
    }
    val digest: ByteArray get() = MessageDigest.getInstance("SHA-256").digest(action)
    fun bytes(): ByteArray {
        require(nonce.size == 32 && expires - issued == 120L)
        // Fixed-width network-order fields, not JSON serialization.
        return "frequency-guardian/diagnostic-approval/v1\u0000".toByteArray(Charsets.US_ASCII) +
            byteArrayOf(1) + nonce + ByteBuffer.allocate(16).putLong(issued).putLong(expires).array() + digest
    }
    fun validate(now: Long) {
        check(!consumed) { "Fixture already consumed" }
        check(System.nanoTime() - createdNanos < 120_000_000_000L) { "Fixture exceeded monotonic lifetime" }
        require(now >= issued && now < expires) { "Fixture expired or clock moved backwards" }
        require(action.contentEquals(ACTION)) { "Unverified action" }
    }
    companion object {
        private val ACTION = "Diagnostic only: verify local signing; authorize no operation.".toByteArray(Charsets.UTF_8)
        fun create(): LocalFixture {
            val now = System.currentTimeMillis() / 1000
            return LocalFixture(ByteArray(32).also { SecureRandom().nextBytes(it) }, now, now + 120, ACTION.copyOf())
        }
    }
}
internal fun ByteArray.hex() = joinToString("") { "%02x".format(it.toInt() and 255) }
internal fun ByteArray.b64(): String = Base64.getEncoder().encodeToString(this)
