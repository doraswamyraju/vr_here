package com.sbr.vrherebms.ui.screens.customer

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
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

@Composable
fun StatusBadgeWidget(status: String) {
    val containerColor = when (status) {
        "Processing at Portal" -> Color(0xFFDBEAFE)
        "Waiting for Clarification" -> Color(0xFFF3E8FF)
        "Completed" -> Color(0xFFD1FAE5)
        "Pending Documents" -> Color(0xFFFEF3C7)
        "Documents Verified" -> Color(0xFFECFDF5)
        else -> Color(0xFFF1F5F9)
    }
    val textColor = when (status) {
        "Processing at Portal" -> Color(0xFF1E40AF)
        "Waiting for Clarification" -> Color(0xFF6B21A8)
        "Completed" -> Color(0xFF065F46)
        "Pending Documents" -> Color(0xFF92400E)
        "Documents Verified" -> Color(0xFF047857)
        else -> Color(0xFF475569)
    }

    Box(
        modifier = Modifier
            .background(containerColor, RoundedCornerShape(12.dp))
            .padding(horizontal = 10.dp, vertical = 5.dp)
    ) {
        Text(
            text = status,
            fontSize = 9.sp,
            fontWeight = FontWeight.Black,
            color = textColor
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
