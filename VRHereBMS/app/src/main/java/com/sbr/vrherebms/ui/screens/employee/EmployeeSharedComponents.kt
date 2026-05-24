package com.sbr.vrherebms.ui.screens.employee

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun EmployeeOverviewStatCard(
    modifier: Modifier = Modifier,
    title: String,
    value: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    color: Color
) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .background(color.copy(alpha = 0.1f), RoundedCornerShape(8.dp)),
                contentAlignment = Alignment.Center
            ) {
                Icon(imageVector = icon, contentDescription = null, tint = color, modifier = Modifier.size(20.dp))
            }
            Spacer(modifier = Modifier.height(12.dp))
            Text(title, fontSize = 11.sp, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold, color = Color(0xFF64748B))
            Text(value, fontSize = 20.sp, fontWeight = androidx.compose.ui.text.font.FontWeight.Black, color = Color(0xFF1E293B), modifier = Modifier.padding(top = 2.dp))
        }
    }
}

fun formatLogTime(dateStr: String): String {
    return try {
        val inputFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.getDefault()).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        val date = inputFormat.parse(dateStr) ?: return dateStr
        val outputFormat = SimpleDateFormat("dd MMM, hh:mm a", Locale.getDefault())
        outputFormat.format(date)
    } catch (e: Exception) {
        dateStr
    }
}
