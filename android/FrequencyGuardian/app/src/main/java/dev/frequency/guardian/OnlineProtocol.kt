package dev.frequency.guardian

import java.net.URI

internal object OnlineProtocol {
    fun endpoint(text: String): String {
        val uri = URI(text)
        require(uri.scheme == "https" && uri.host != null && uri.rawUserInfo == null &&
            uri.rawQuery == null && uri.rawFragment == null && uri.rawPath in listOf("", "/") &&
            (uri.port == -1 || uri.port in 1..65535)) { "Use HTTPS origin only; no credentials, path, query or fragment" }
        return text.removeSuffix("/")
    }
    fun token(text: String): String {
        require(text.matches(Regex("[A-Za-z0-9_-]{43}"))) { "Expected operator-issued pairing token" }
        return text
    }
}
