package com.sbr.vrherebms.ui.screens.customer.bookkeeping.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.CalendarMonth
import androidx.compose.material3.Icon
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun BookkeepingDateFilterBar(
    financialYear: String,
    selectedMonth: String,
    monthsList: List<String>,
    onMonthChange: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val primaryIndigo = Color(0xFF4F46E5)
    val textDark = Color(0xFF0F172A)
    val textMuted = Color(0xFF64748B)

    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        // Financial Year Badge
        Surface(
            shape = RoundedCornerShape(10.dp),
            color = Color.White,
            border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
            shadowElevation = 0.5.dp
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.CalendarMonth,
                    contentDescription = null,
                    tint = primaryIndigo,
                    modifier = Modifier.size(15.dp)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = financialYear,
                    fontSize = 11.5.sp,
                    fontWeight = FontWeight.Bold,
                    color = textDark
                )
            }
        }

        // Month Switcher Carousel Controls
        Surface(
            shape = RoundedCornerShape(10.dp),
            color = Color.White,
            border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
            shadowElevation = 0.5.dp
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp)
            ) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = "Previous Month",
                    tint = textMuted,
                    modifier = Modifier
                        .size(18.dp)
                        .clickable {
                            val idx = monthsList.indexOf(selectedMonth)
                            if (idx > 0) onMonthChange(monthsList[idx - 1])
                        }
                )
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    text = selectedMonth,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Black,
                    color = primaryIndigo
                )
                Spacer(modifier = Modifier.width(10.dp))
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                    contentDescription = "Next Month",
                    tint = textMuted,
                    modifier = Modifier
                        .size(18.dp)
                        .clickable {
                            val idx = monthsList.indexOf(selectedMonth)
                            if (idx < monthsList.size - 1) onMonthChange(monthsList[idx + 1])
                        }
                )
            }
        }
    }
}
