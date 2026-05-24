package com.sbr.vrherebms.ui.screens.partner

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.text.NumberFormat
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun PartnerStatCard(
    modifier: Modifier = Modifier,
    title: String,
    value: String,
    label: String,
    icon: ImageVector,
    iconBg: Color,
    iconColor: Color
) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Box(
                    modifier = Modifier
                        .size(34.dp)
                        .background(iconBg, RoundedCornerShape(8.dp)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(imageVector = icon, contentDescription = null, tint = iconColor, modifier = Modifier.size(18.dp))
                }
                Text(
                    text = label,
                    fontSize = 8.sp,
                    fontWeight = androidx.compose.ui.text.font.FontWeight.Black,
                    color = Color(0xFF94A3B8)
                )
            }
            Spacer(modifier = Modifier.height(10.dp))
            Text(title, fontSize = 10.sp, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold, color = Color(0xFF64748B))
            Text(value, fontSize = 18.sp, fontWeight = androidx.compose.ui.text.font.FontWeight.Black, color = Color(0xFF1E293B), modifier = Modifier.padding(top = 2.dp))
        }
    }
}

@Composable
fun DetailRow(label: String, value: String) {
    Row(
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(label, fontSize = 11.sp, color = Color(0xFF64748B), fontWeight = androidx.compose.ui.text.font.FontWeight.Medium)
        Text(value, fontSize = 11.sp, color = Color(0xFF1E293B), fontWeight = androidx.compose.ui.text.font.FontWeight.Black)
    }
}

fun formatINR(amount: Double): String {
    return try {
        val format = NumberFormat.getCurrencyInstance(Locale("en", "IN"))
        format.maximumFractionDigits = 0
        format.format(amount).replace("Rs.", "₹").replace("INR", "₹")
    } catch (e: Exception) {
        "₹${amount.toInt()}"
    }
}

fun formatDate(dateStr: String): String {
    return try {
        val inputFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.getDefault()).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        val date = inputFormat.parse(dateStr) ?: return dateStr
        val outputFormat = SimpleDateFormat("dd MMM yyyy", Locale.getDefault())
        outputFormat.format(date)
    } catch (e: Exception) {
        dateStr.split("T").firstOrNull() ?: dateStr
    }
}
