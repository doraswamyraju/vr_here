package com.sbr.vrherebms.ui.screens.hrms

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.LeaveResponse
import com.sbr.vrherebms.data.model.LiveStatusEmployee
import com.sbr.vrherebms.data.model.NoticeResponse
import com.sbr.vrherebms.data.model.HolidayResponse

@Composable
fun LiveEmployeeCard(
    emp: LiveStatusEmployee,
    isWorking: Boolean = false,
    isOnLeave: Boolean = false,
    isOffline: Boolean = false
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(12.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .background(Color(0xFFF1F5F9), RoundedCornerShape(20.dp)),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = emp.name.firstOrNull()?.toString()?.uppercase() ?: "E",
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF475569)
                )
            }

            Column(modifier = Modifier.weight(1f)) {
                Text(emp.name, fontSize = 14.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                Text(emp.email, fontSize = 11.sp, color = Color.Gray)

                if (isWorking && emp.clockInAt != null) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Working via ${emp.source ?: "Web"} | In: ${emp.clockInAt.take(16).replace("T", " ")}",
                        fontSize = 10.sp,
                        color = Color(0xFF059669),
                        fontWeight = FontWeight.SemiBold
                    )
                }

                if (isOnLeave) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "On ${emp.leaveType} Leave: \"${emp.reason}\"",
                        fontSize = 11.sp,
                        color = Color(0xFF2563EB),
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }
        }
    }
}

@Composable
fun NoticeCard(notice: NoticeResponse) {
    val accentColor = when (notice.priority) {
        "High" -> Color(0xFFEF4444)
        "Medium" -> Color(0xFFF59E0B)
        else -> Color(0xFF64748B)
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(14.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = notice.title,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF1E293B),
                    modifier = Modifier.weight(1f)
                )
                Surface(
                    color = accentColor.copy(alpha = 0.1f),
                    shape = RoundedCornerShape(6.dp)
                ) {
                    Text(
                        text = notice.priority,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = accentColor,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = notice.message,
                fontSize = 13.sp,
                color = Color(0xFF475569),
                lineHeight = 18.sp
            )

            Spacer(modifier = Modifier.height(12.dp))
            HorizontalDivider(color = Color(0xFFF1F5F9))
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "Issued by Admin on ${notice.createdAt.take(10)}",
                fontSize = 10.sp,
                color = Color.Gray
            )
        }
    }
}

@Composable
fun HolidayCard(holiday: HolidayResponse) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(14.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Calendar icon placeholder
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .background(Color(0xFFEEF2FF), RoundedCornerShape(12.dp)),
                contentAlignment = Alignment.Center
            ) {
                Text("📅", fontSize = 20.sp)
            }

            Column(modifier = Modifier.weight(1f)) {
                Text(holiday.title, fontSize = 14.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                Text("Date: ${holiday.date.take(10)}", fontSize = 11.sp, color = Color(0xFF4F46E5), fontWeight = FontWeight.Bold)
                if (holiday.description.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = holiday.description,
                        fontSize = 12.sp,
                        color = Color.Gray,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }
    }
}

@Composable
fun LeaveHistoryCard(leave: LeaveResponse) {
    val statusColor = when (leave.status) {
        "Approved" -> Color(0xFF10B981)
        "Rejected" -> Color(0xFFEF4444)
        else -> Color(0xFFF59E0B)
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(14.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.between,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("${leave.type} Leave", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                Surface(
                    color = statusColor.copy(alpha = 0.1f),
                    shape = RoundedCornerShape(6.dp)
                ) {
                    Text(
                        text = leave.status,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = statusColor,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }
            }

            Text("Duration: ${leave.startDate.take(10)} to ${leave.endDate.take(10)}", fontSize = 12.sp, color = Color.Gray)
            Text("Reason: ${leave.reason}", fontSize = 12.sp, color = Color(0xFF475569))

            if (!leave.adminNotes.isNullOrEmpty()) {
                Spacer(modifier = Modifier.height(4.dp))
                HorizontalDivider(color = Color(0xFFF8FAFC))
                Spacer(modifier = Modifier.height(4.dp))
                Text("Admin Remarks: \"${leave.adminNotes}\"", fontSize = 11.sp, color = Color(0xFF94A3B8))
            }
        }
    }
}
