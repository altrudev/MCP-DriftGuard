package dev.frequency.guardian

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import java.io.File

/** Exactly one nonsecret cache file; no arbitrary paths, writes, or key access. */
class SettingsProvider : ContentProvider() {
    override fun onCreate() = true
    private fun file(uri: Uri): File {
        require(uri.toString() == "content://${context!!.packageName}.settings/settings.json")
        return File(context!!.cacheDir, "settings.json")
    }
    override fun getType(uri: Uri): String { file(uri); return "application/json" }
    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        require(mode == "r")
        return ParcelFileDescriptor.open(file(uri), ParcelFileDescriptor.MODE_READ_ONLY)
    }
    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor {
        val f = file(uri)
        val columns = projection ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        require(columns.all { it == OpenableColumns.DISPLAY_NAME || it == OpenableColumns.SIZE })
        return MatrixCursor(columns).apply { addRow(columns.map { if (it == OpenableColumns.DISPLAY_NAME) "frequency-guardian-settings.json" else f.length() }) }
    }
    override fun insert(uri: Uri, values: ContentValues?): Uri? = throw UnsupportedOperationException()
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = throw UnsupportedOperationException()
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = throw UnsupportedOperationException()
}
