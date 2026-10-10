package com.sbr.vrherebms.ui.screens.admin.modules

import androidx.compose.animation.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.AttendanceSummaryItem
import com.sbr.vrherebms.data.model.EmployeeResponse
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminPerformanceScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var selectedEmployeeId by remember { mutableStateOf<String?>(null) }
    var selectedTimeframe by remember { mutableStateOf("30 Days") }
    var expandedEmployeeMenu by remember { mutableStateOf(false) }

    val selectedEmployee = remember(selectedEmployeeId, adminViewModel.employees) {
        adminViewModel.employees.firstOrNull { it.idVal == selectedEmployeeId }
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF8FAFC)),
        contentPadding = PaddingValues(bottom = 90.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // 1. Dark Command Header
        item {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A))
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Text(
                        text = "WORKFORCE PRODUCTIVITY & PERFORMANCE",
                        color = Color(0xFF38BDF8),
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Black,
                        letterSpacing = 1.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Performance Analytics",
                        color = Color.White,
                        fontSize = 22.sp,
                        fontWeight = FontWeight.Black
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Deep dive into employee time tracking, productivity ratios, task completion, and daily timesheet logs.",
                        color = Color(0xFF94A3B8),
                        fontSize = 12.sp,
                        lineHeight = 16.sp
                    )
                }
            }
        }

        // 2. Specialist Selector & Timeframe Presets
        item {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "SELECT SPECIALIST",
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF64748B)
                )

                Box(modifier = Modifier.fillMaxWidth()) {
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { expandedEmployeeMenu = true },
                        shape = RoundedCornerShape(12.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(12.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = selectedEmployee?.name ?: "All Team Specialists",
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF1E293B)
                            )
                            Icon(
                                imageVector = Icons.Default.UnfoldMore,
                                contentDescription = null,
                                tint = Color(0xFF64748B),
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }

                    DropdownMenu(
                        expanded = expandedEmployeeMenu,
                        onDismissRequest = { expandedEmployeeMenu = false },
                        modifier = Modifier.fillMaxWidth(0.9f)
                    ) {
                        DropdownMenuItem(
                            text = { Text("All Team Specialists", fontWeight = FontWeight.Bold) },
                            onClick = {
                                selectedEmployeeId = null
                                expandedEmployeeMenu = false
                            }
                        )
                        adminViewModel.employees.forEach { emp ->
                            DropdownMenuItem(
                                text = { Text("${emp.name} (${emp.role})") },
                                onClick = {
                                    selectedEmployeeId = emp.idVal
                                    expandedEmployeeMenu = false
                                }
                            )
                        }
                    }
                }

                // Timeframe Chips
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf("7 Days", "30 Days", "90 Days").forEach { tf ->
                        val isSel = selectedTimeframe == tf
                        Card(
                            modifier = Modifier.clickable { selectedTimeframe = tf },
                            shape = RoundedCornerShape(8.dp),
                            colors = CardDefaults.cardColors(
                                containerColor = if (isSel) Color(0xFF6366F1) else Color.White
                            ),
                            border = BorderStroke(1.dp, if (isSel) Color(0xFF6366F1) else Color(0xFFE2E8F0))
                        ) {
                            Text(
                                text = tf,
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                color = if (isSel) Color.White else Color(0xFF1E293B)
                            )
                        }
                    }
                }
            }
        }

        // 3. Summary KPI Cards
        item {
            val targetOrders = remember(selectedEmployeeId, adminViewModel.orders) {
                if (selectedEmployeeId == null) {
                    adminViewModel.orders
                } else {
                    adminViewModel.orders.filter {
                        it.assignedEmployee?.idVal == selectedEmployeeId ||
                                it.assignedMaker?.idVal == selectedEmployeeId ||
                                it.assignedChecker?.idVal == selectedEmployeeId ||
                                it.assignedProjectManager?.idVal == selectedEmployeeId
                    }
                }
            }
            val totalAssigned = targetOrders.size
            val totalCompleted = targetOrders.count { it.status == "Completed" }
            val avgRate = if (totalAssigned == 0) 100 else (totalCompleted * 100) / totalAssigned

            val matchedAtt = remember(selectedEmployeeId, adminViewModel.attendanceItems) {
                adminViewModel.attendanceItems.filter {
                    selectedEmployeeId == null || it.id == selectedEmployeeId
                }
            }
            val totalMinutes = matchedAtt.sumOf { it.trackedMinutes }
            val hours = totalMinutes / 60
            val mins = totalMinutes % 60

            LazyRow(
                modifier = Modifier.fillMaxWidth(),
                contentPadding = PaddingValues(horizontal = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                item {
                    KpiCard(title = "TRACKED TIME", value = "${hours}h ${mins}m", sub = "Recorded Effort", color = Color(0xFF6366F1))
                }
                item {
                    KpiCard(title = "ASSIGNED JOBS", value = "$totalAssigned", sub = "Active Operations", color = Color(0xFF3B82F6))
                }
                item {
                    KpiCard(title = "DELIVERIES", value = "$totalCompleted", sub = "Completed Orders", color = Color(0xFF10B981))
                }
                item {
                    KpiCard(title = "AVG SLA WIN", value = "$avgRate%", sub = "Fulfillment Quality", color = Color(0xFFA855F7))
                }
            }
        }

        // 4. Selected Employee Deep-Dive Worksheet
        if (selectedEmployee != null) {
            val emp = selectedEmployee
            item {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text(
                        text = "WORKSHEET & TIME LOG • ${emp.name.uppercase()}",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFF64748B)
                    )

                    val empAttendance = adminViewModel.attendanceItems.filter { it.id == emp.idVal }

                    if (empAttendance.isEmpty()) {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(14.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                        ) {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(24.dp),
                                horizontalAlignment = Alignment.CenterHorizontally,
                                verticalArrangement = Arrangement.Center
                            ) {
                                Icon(Icons.Default.EventBusy, contentDescription = null, tint = Color(0xFF94A3B8), modifier = Modifier.size(32.dp))
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(
                                    text = "No attendance or worksheet entries in this date range.",
                                    fontSize = 12.sp,
                                    color = Color(0xFF64748B)
                                )
                            }
                        }
                    } else {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            empAttendance.forEach { att ->
                                Card(
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(12.dp),
                                    colors = CardDefaults.cardColors(containerColor = Color.White),
                                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                                ) {
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(12.dp),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Row(
                                            verticalAlignment = Alignment.CenterVertically,
                                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                                        ) {
                                            Box(
                                                modifier = Modifier
                                                    .size(8.dp)
                                                    .background(
                                                        if (att.isClockedIn) Color(0xFF10B981) else Color(0xFF94A3B8),
                                                        CircleShape
                                                    )
                                            )
                                            Column {
                                                Text(att.name, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                                                Text(
                                                    text = if (att.isClockedIn) "Clocked In: ${att.clockInAt ?: "Active"}" else "Offline",
                                                    fontSize = 10.sp,
                                                    color = Color(0xFF64748B)
                                                )
                                            }
                                        }

                                        Text(
                                            text = "${att.trackedMinutes / 60}h ${att.trackedMinutes % 60}m",
                                            fontSize = 11.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = Color(0xFF6366F1)
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 5. Team Leaderboard & Capacity
        item {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "EMPLOYEE LEADERBOARD & CAPACITY",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF64748B)
                )

                val targetEmployees = if (selectedEmployeeId == null) {
                    adminViewModel.employees
                } else {
                    adminViewModel.employees.filter { it.idVal == selectedEmployeeId }
                }

                if (targetEmployees.isEmpty()) {
                    Text("No employees registered", fontSize = 12.sp, color = Color(0xFF94A3B8), modifier = Modifier.padding(vertical = 12.dp))
                } else {
                    targetEmployees.forEach { emp ->
                        val assignedOrders = adminViewModel.orders.filter {
                            it.assignedEmployee?.idVal == emp.idVal ||
                                    it.assignedMaker?.idVal == emp.idVal ||
                                    it.assignedChecker?.idVal == emp.idVal ||
                                    it.assignedProjectManager?.idVal == emp.idVal
                        }
                        val completed = assignedOrders.count { it.status == "Completed" }
                        val pending = assignedOrders.size - completed
                        val completionRate = if (assignedOrders.isEmpty()) 100 else (completed * 100) / assignedOrders.size

                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                        ) {
                            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                                    ) {
                                        Box(
                                            modifier = Modifier
                                                .size(40.dp)
                                                .background(Color(0xFF3B82F6).copy(alpha = 0.12f), CircleShape),
                                            contentAlignment = Alignment.Center
                                        ) {
                                            Text(
                                                text = emp.name.take(1).uppercase(),
                                                color = Color(0xFF3B82F6),
                                                fontSize = 14.sp,
                                                fontWeight = FontWeight.Black
                                            )
                                        }
                                        Column {
                                            Text(emp.name, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                                            Text(emp.email, fontSize = 10.sp, color = Color(0xFF64748B))
                                        }
                                    }

                                    val isGood = completionRate >= 75
                                    Box(
                                        modifier = Modifier
                                            .background(
                                                (if (isGood) Color(0xFF10B981) else Color(0xFFF59E0B)).copy(alpha = 0.12f),
                                                RoundedCornerShape(6.dp)
                                            )
                                            .padding(horizontal = 8.dp, vertical = 4.dp)
                                    ) {
                                        Text(
                                            text = "$completionRate% SLA",
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.Black,
                                            color = if (isGood) Color(0xFF10B981) else Color(0xFFF59E0B)
                                        )
                                    }
                                }

                                // Linear Progress Bar
                                Box(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .height(8.dp)
                                        .clip(RoundedCornerShape(4.dp))
                                        .background(Color(0xFFF1F5F9))
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .fillMaxHeight()
                                            .fillMaxWidth(completionRate / 100f)
                                            .background(if (completionRate >= 75) Color(0xFF10B981) else Color(0xFFF59E0B))
                                    )
                                }

                                Divider(color = Color(0xFFF1F5F9))

                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Column {
                                        Text("TOTAL CASES", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                                        Text("${assignedOrders.size}", fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                                    }
                                    Column {
                                        Text("ACTIVE PIPELINE", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                                        Text("$pending", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF3B82F6))
                                    }
                                    Column(horizontalAlignment = Alignment.End) {
                                        Text("CLOSED DELIVERIES", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                                        Text("$completed", fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color(0xFF10B981))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun KpiCard(
    title: String,
    value: String,
    sub: String,
    color: Color
) {
    Card(
        modifier = Modifier.width(140.dp),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, color.copy(alpha = 0.2f))
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(title, fontSize = 9.sp, fontWeight = FontWeight.Black, color = color, letterSpacing = 0.5.sp)
            Spacer(modifier = Modifier.height(4.dp))
            Text(value, fontSize = 20.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
            Spacer(modifier = Modifier.height(2.dp))
            Text(sub, fontSize = 9.sp, color = Color(0xFF64748B))
        }
    }
}
