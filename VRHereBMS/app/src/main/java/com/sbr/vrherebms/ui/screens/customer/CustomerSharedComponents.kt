package com.sbr.vrherebms.ui.screens.customer

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import android.widget.Toast
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.MultipartBody
import okhttp3.RequestBody.Companion.asRequestBody
import java.io.File
import java.io.FileOutputStream

@Composable
fun StatusBadgeWidget(status: String) {
    val containerColor = when (status) {
        "Processing at Portal" -> Color(0xFFDBEAFE)
        "Waiting for Clarification" -> Color(0xFFFEF3C7)
        "Completed" -> Color(0xFFD1FAE5)
        "Pending Documents" -> Color(0xFFFFE4E6)
        "Documents Verified" -> Color(0xFFE0E7FF)
        else -> Color(0xFFF1F5F9)
    }
    val textColor = when (status) {
        "Processing at Portal" -> Color(0xFF1D4ED8)
        "Waiting for Clarification" -> Color(0xFFB45309)
        "Completed" -> Color(0xFF047857)
        "Pending Documents" -> Color(0xFFBE123C)
        "Documents Verified" -> Color(0xFF4338CA)
        else -> Color(0xFF64748B)
    }
    val borderColor = when (status) {
        "Processing at Portal" -> Color(0xFFBFDBFE)
        "Waiting for Clarification" -> Color(0xFFFDE68A)
        "Completed" -> Color(0xFFA7F3D0)
        "Pending Documents" -> Color(0xFFFECDD3)
        "Documents Verified" -> Color(0xFFC7D2FE)
        else -> Color(0xFFE2E8F0)
    }

    Surface(
        color = containerColor,
        shape = RoundedCornerShape(8.dp),
        border = BorderStroke(1.dp, borderColor)
    ) {
        Text(
            text = status.uppercase(),
            fontSize = 9.sp,
            fontWeight = FontWeight.Black,
            color = textColor,
            letterSpacing = 0.5.sp,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
        )
    }
}

fun getStatusProgress(status: String): Int {
    return when (status) {
        "Pending Documents" -> 20
        "Documents Verified" -> 40
        "Processing at Portal" -> 60
        "Waiting for Clarification" -> 70
        "Completed" -> 100
        else -> 0
    }
}

@Composable
fun Modifier.scaleOnPress(scale: Float = 0.95f): Modifier {
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()
    val animatedScale by animateFloatAsState(if (isPressed) scale else 1f, label = "ScaleOnPress")
    return this.graphicsLayer {
        scaleX = animatedScale
        scaleY = animatedScale
    }
}

/**
 * Safely opens a document web URL in the browser / system viewer.
 * Fixes relative paths and missing http/https prefixes so Android doesn't prompt for email/mail apps.
 */
fun openDocumentUrl(context: Context, rawUrl: String?) {
    if (rawUrl.isNullOrBlank()) {
        Toast.makeText(context, "No document URL available", Toast.LENGTH_SHORT).show()
        return
    }
    val cleanUrl = rawUrl.trim()
    val formattedUrl = when {
        cleanUrl.startsWith("http://", ignoreCase = true) || cleanUrl.startsWith("https://", ignoreCase = true) -> cleanUrl
        cleanUrl.startsWith("www.", ignoreCase = true) -> "https://$cleanUrl"
        else -> "https://vrhere.in/${cleanUrl.trimStart('/')}"
    }

    try {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(formattedUrl)).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(intent)
    } catch (e: Exception) {
        Toast.makeText(context, "Unable to open document", Toast.LENGTH_SHORT).show()
    }
}

fun uriToMultipartPart(context: Context, uri: Uri, paramName: String = "document"): MultipartBody.Part? {
    return try {
        val contentResolver = context.contentResolver
        val type = contentResolver.getType(uri) ?: "application/octet-stream"
        val inputStream = contentResolver.openInputStream(uri) ?: return null
        val tempFile = File.createTempFile("upload_", ".tmp", context.cacheDir)
        tempFile.outputStream().use { output ->
            inputStream.copyTo(output)
        }
        val reqFile = tempFile.asRequestBody(type.toMediaTypeOrNull())
        MultipartBody.Part.createFormData(paramName, tempFile.name, reqFile)
    } catch (e: Exception) {
        null
    }
}

fun bitmapToMultipartPart(context: Context, bitmap: Bitmap, paramName: String = "document"): MultipartBody.Part? {
    return try {
        val tempFile = File.createTempFile("photo_", ".jpg", context.cacheDir)
        FileOutputStream(tempFile).use { out ->
            bitmap.compress(Bitmap.CompressFormat.JPEG, 90, out)
        }
        val reqFile = tempFile.asRequestBody("image/jpeg".toMediaTypeOrNull())
        MultipartBody.Part.createFormData(paramName, "photo_${System.currentTimeMillis()}.jpg", reqFile)
    } catch (e: Exception) {
        null
    }
}
