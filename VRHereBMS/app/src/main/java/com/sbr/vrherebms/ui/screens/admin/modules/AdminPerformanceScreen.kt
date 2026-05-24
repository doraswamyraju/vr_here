package com.sbr.vrherebms.ui.screens.admin.modules

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminPerformanceScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var selectedEmployeeId by remember { mutableStateOf<String?>(null) }
    var selectedEmployeeName by remember { mutableStateOf("Select Specialist") }
    var expandedEmployee by remember { mutableStateOf(false) }

    // Custom stats for the selected employee
    val hasSelected = selectedEmployeeId != null

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF1F5F9))
    ) {
        // 1. Sleek Command Header
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1B4B))
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Text(
                    text = "PERFORMANCE ANALYTICS",
                    color = Color(0xFF38BDF8),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.ExtraBold,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Workload & Efficiency",
                    color = Color.White,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Deep dive into employee time tracking, active workloads, and task completion metrics.",
                    color = Color(0xFF94A3B8),
                    fontSize = 12.sp,
                    lineHeight = 16.sp
                )
            }
        }

        // 2. Select Employee Box
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp)
        ) {
            OutlinedTextField(
                value = selectedEmployeeName,
                onValueChange = {},
                readOnly = true,
                label = { Text("Specialist Worksheet", fontWeight = FontWeight.Bold) },
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { expandedEmployee = true },
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = Color.White,
                    unfocusedContainerColor = Color.White,
                    focusedBorderColor = Color(0xFF4F46E5),
                    unfocusedBorderColor = Color(0xFFE2E8F0)
                ),
                trailingIcon = {
                    IconButton(onClick = { expandedEmployee = true }) {
                        Icon(Icons.Default.ArrowDropDown, contentDescription = null)
                    }
                }
            )

            DropdownMenu(
                expanded = expandedEmployee,
                onDismissRequest = { expandedEmployee = false },
                modifier = Modifier.fillMaxWidth(0.9f)
            ) {
                DropdownMenuItem(
                    text = { Text("Ramesh Kumar (CA Specialist)") },
                    onClick = {
                        selectedEmployeeId = "ramesh"
                        selectedEmployeeName = "Ramesh Kumar"
                        expandedEmployee = false
                    }
                )
                adminViewModel.employees.forEach { emp ->
                    DropdownMenuItem(
                        text = { Text("${emp.name} (${emp.role})") },
                        onClick = {
                            selectedEmployeeId = emp.id
                            selectedEmployeeName = emp.name
                            expandedEmployee = false
                        }
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        if (!hasSelected) {
            // Unselected welcome board
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .padding(24.dp),
                contentAlignment = Alignment.Center
            ) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(
                        modifier = Modifier.padding(32.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Box(
                            modifier = Modifier
                                .size(64.dp)
                                .background(Color(0xFFEEF2F6), CircleShape),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.TrendingUp, contentDescription = null, tint = Color(0xFF4F46E5), modifier = Modifier.size(32.dp))
                        }
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            text = "No Employee Selected",
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF1E293B)
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "Please select a staff member from the dropdown above to audit their live timecards, work sheets, and rating analysis.",
                            fontSize = 12.sp,
                            color = Color(0xFF64748B),
                            textAlign = TextAlign.Center,
                            lineHeight = 18.sp
                        )
                    }
                }
            }
        } else {
            // Selected detailed performance board
            LazyColumn(
                modifier = Modifier
                    .weight(1f)
                    .padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Row 1: Metrics
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        listOf(
                            Triple("Total Logged", "42 hrs", "Sessions: 14"),
                            Triple("Utilization", "88%", "Productivity Index")
                        ).forEach { (title, stat, sub) ->
                            Card(
                                modifier = Modifier.weight(1f),
                                colors = CardDefaults.cardColors(containerColor = Color.White),
                                border = BorderStroke(1.dp, Color(0xFFEEF2F6)),
                                shape = RoundedCornerShape(16.dp)
                            ) {
                                Column(modifier = Modifier.padding(16.dp)) {
                                    Text(title, fontSize = 9.sp, color = Color(0xFF64748B), fontWeight = FontWeight.Black)
                                    Spacer(modifier = Modifier.height(6.dp))
                                    Text(stat, fontSize = 22.sp, color = Color(0xFF1E293B), fontWeight = FontWeight.Black)
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(sub, fontSize = 9.sp, color = Color(0xFF10B981), fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }
                }

                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        listOf(
                            Triple("Active Workload", "3 Orders", "In Progress Tasks"),
                            Triple("Resolution Speed", "1.4 Days", "Target: Under 2.0")
                        ).forEach { (title, stat, sub) ->
                            Card(
                                modifier = Modifier.weight(1f),
                                colors = CardDefaults.cardColors(containerColor = Color.White),
                                border = BorderStroke(1.dp, Color(0xFFEEF2F6)),
                                shape = RoundedCornerShape(16.dp)
                            ) {
                                Column(modifier = Modifier.padding(16.dp)) {
                                    Text(title, fontSize = 9.sp, color = Color(0xFF64748B), fontWeight = FontWeight.Black)
                                    Spacer(modifier = Modifier.height(6.dp))
                                    Text(stat, fontSize = 22.sp, color = Color(0xFF1E293B), fontWeight = FontWeight.Black)
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(sub, fontSize = 9.sp, color = Color(0xFF4F46E5), fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }
                }

                // Header
                item {
                    Text("Workload Analysis Details", color = Color(0xFF1E293B), fontWeight = FontWeight.Bold, fontSize = 15.sp)
                }

                // Analysis entries
                items(
                    listOf(
                        Triple("Private Limited Registration (Rajugari Ventures)", "Time Logged: 18h 45m", "Status: Documentation Reviewing"),
                        Triple("GST Quarterly Filing (Blue Cat Solutions)", "Time Logged: 12h 10m", "Status: Awaiting Verification"),
                        Triple("Trademark Audit Response (Gayatri Enterprises)", "Time Logged: 11h 05m", "Status: Ready for Objections")
                    )
                ) { (service, logs, status) ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        shape = RoundedCornerShape(16.dp),
                        border = BorderStroke(1.dp, Color(0xFFEEF2F6))
                    ) {
                        Row(
                            modifier = Modifier.padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(36.dp)
                                    .background(Color(0xFFEFF6FF), RoundedCornerShape(8.dp)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(Icons.Default.Assignment, contentDescription = null, tint = Color(0xFF3B82F6), modifier = Modifier.size(18.dp))
                            }
                            Spacer(modifier = Modifier.width(16.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(service, fontWeight = FontWeight.Bold, fontSize = 13.sp, color = Color(0xFF1E293B))
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(logs, fontSize = 11.sp, color = Color(0xFF64748B), fontWeight = FontWeight.Medium)
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(status, fontSize = 10.sp, color = Color(0xFF10B981), fontWeight = FontWeight.ExtraBold)
                            }
                        }
                    }
                }
            }
        }
    }
}
