package com.sbr.vrherebms.ui.screens.employee

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccessTime
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.EmployeeDashboardViewModel

@Composable
fun EmployeeAttendanceTab(viewModel: EmployeeDashboardViewModel) {
    val isClockedIn = viewModel.isClockedIn
    val logs = viewModel.attendanceLogs

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Text(
                        "Attendance Clock",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFF1E293B)
                    )
                    Text(
                        if (isClockedIn) "You are currently clocked in." else "You are clocked out.",
                        fontSize = 12.sp,
                        color = Color(0xFF64748B)
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    val buttonColor = if (isClockedIn) Color(0xFFEF4444) else Color(0xFF10B981)

                    Box(
                        modifier = Modifier
                            .size(120.dp)
                            .background(buttonColor.copy(alpha = 0.1f), CircleShape)
                            .padding(12.dp)
                            .background(buttonColor, CircleShape)
                            .clickable { viewModel.toggleClockStatus() },
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            if (isClockedIn) "CLOCK OUT" else "CLOCK IN",
                            color = Color.White,
                            fontWeight = FontWeight.Black,
                            fontSize = 13.sp
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    if (!isClockedIn) {
                        OutlinedTextField(
                            value = viewModel.clockInNote,
                            onValueChange = { viewModel.clockInNote = it },
                            label = { Text("Clock In Notes (Optional)") },
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }
            }
        }

        item {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Start) {
                Text(
                    "Log History",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF1E293B),
                    modifier = Modifier.padding(top = 8.dp)
                )
            }
        }

        if (logs.isEmpty()) {
            item {
                Text("No logs registered for today.", color = Color(0xFF94A3B8), fontSize = 12.sp)
            }
        } else {
            items(logs) { log ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(14.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(36.dp)
                                .background(Color(0xFFEEF2F6), CircleShape),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.AccessTime, contentDescription = null, tint = Color(0xFF64748B))
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                "In: ${formatLogTime(log.clockInAt)}",
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp,
                                color = Color(0xFF1E293B)
                            )
                            if (log.notes.isNotEmpty()) {
                                Text(log.notes, fontSize = 11.sp, color = Color(0xFF64748B))
                            }
                        }
                        Box(
                            modifier = Modifier
                                .background(
                                    color = if (log.clockOutAt != null) Color(0xFFE2E8F0) else Color(0xFFD1FAE5),
                                    shape = RoundedCornerShape(6.dp)
                                )
                                .padding(horizontal = 8.dp, vertical = 4.dp)
                        ) {
                            Text(
                                text = if (log.clockOutAt != null) "Completed" else "Active",
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Black,
                                color = if (log.clockOutAt != null) Color(0xFF64748B) else Color(0xFF065F46)
                            )
                        }
                    }
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(60.dp))
        }
    }
}
