package com.sbr.vrherebms.ui.screens

import android.widget.Toast
import androidx.compose.animation.*
import androidx.compose.foundation.background
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
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.AttendanceResponse
import com.sbr.vrherebms.viewmodel.EmployeeDashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EmployeeDashboardScreen(
    viewModel: EmployeeDashboardViewModel,
    userName: String,
    onLogout: () -> Unit
) {
    var activeTab by remember { mutableStateOf("Tasks") }
    val context = LocalContext.current

    LaunchedEffect(key1 = true) {
        viewModel.syncDashboardData()
        viewModel.eventFlow.collect { event ->
            if (event is EmployeeDashboardViewModel.UiEvent.ShowToast) {
                Toast.makeText(context, event.message, Toast.LENGTH_SHORT).show()
            }
        }
    }

    val primaryGradient = listOf(Color(0xFF0EA5E9), Color(0xFF2563EB)) // Sky to Blue

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(36.dp)
                                .background(
                                    brush = Brush.linearGradient(primaryGradient),
                                    shape = RoundedCornerShape(10.dp)
                                ),
                            contentAlignment = Alignment.Center
                        ) {
                            Text("VR", color = Color.White, fontWeight = FontWeight.Black, fontSize = 16.sp)
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                "Employee Workspace",
                                fontSize = 15.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF1E293B)
                            )
                            Text(
                                "Logged in as $userName",
                                fontSize = 11.sp,
                                color = Color(0xFF64748B)
                            )
                        }
                    }
                },
                actions = {
                    IconButton(onClick = { viewModel.syncDashboardData() }) {
                        Icon(Icons.Default.Refresh, contentDescription = "Refresh")
                    }
                    IconButton(onClick = onLogout) {
                        Icon(Icons.Default.LogOut, contentDescription = "Logout", tint = Color(0xFFEF4444))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.White)
            )
        },
        bottomBar = {
            NavigationBar(containerColor = Color.White) {
                NavigationBarItem(
                    selected = activeTab == "Tasks",
                    onClick = { activeTab = "Tasks" },
                    icon = { Icon(Icons.Default.Task, contentDescription = "Tasks") },
                    label = { Text("My Tasks", fontSize = 11.sp, fontWeight = FontWeight.Bold) }
                )
                NavigationBarItem(
                    selected = activeTab == "Attendance",
                    onClick = { activeTab = "Attendance" },
                    icon = { Icon(Icons.Default.AccessTime, contentDescription = "Attendance") },
                    label = { Text("Attendance", fontSize = 11.sp, fontWeight = FontWeight.Bold) }
                )
            }
        }
    ) { paddingValues ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .background(Color(0xFFF8FAFC))
        ) {
            when (activeTab) {
                "Tasks" -> EmployeeTasksTab(viewModel)
                "Attendance" -> EmployeeAttendanceTab(viewModel)
            }
        }
    }
}

@Composable
fun EmployeeTasksTab(viewModel: EmployeeDashboardViewModel) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Text("Assigned Projects", fontSize = 18.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
            Text("Manage steps and verify document compliance for registered clients.", fontSize = 12.sp, color = Color(0xFF64748B))
        }

        if (viewModel.assignedOrders.isEmpty()) {
            item {
                Box(modifier = Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                    Text("No projects currently assigned to you.", color = Color(0xFF64748B))
                }
            }
        } else {
            items(viewModel.assignedOrders) { order ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(36.dp)
                                    .background(Color(0xFFEEF2F6), RoundedCornerShape(10.dp)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(Icons.Default.FolderOpen, contentDescription = null, tint = Color(0xFF0EA5E9))
                            }
                            Spacer(modifier = Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(order.serviceName, fontWeight = FontWeight.Black, fontSize = 14.sp, color = Color(0xFF1E293B))
                                Text("Client: ${order.clientName} (${order.email})", fontSize = 12.sp, color = Color(0xFF64748B))
                            }
                        }
                        Divider(modifier = Modifier.padding(vertical = 12.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("Current Milestone: ${order.status}", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF64748B))
                            Box(
                                modifier = Modifier
                                    .background(Color(0xFFEEF2F6), RoundedCornerShape(6.dp))
                                    .padding(horizontal = 6.dp, vertical = 3.dp)
                            ) {
                                Text("In Progress", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF2563EB))
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun EmployeeAttendanceTab(viewModel: EmployeeDashboardViewModel) {
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
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = "Attendance Clock",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFF1E293B)
                    )
                    Text(
                        text = if (viewModel.isClockedIn) "You are currently clocked in." else "You are clocked out.",
                        fontSize = 13.sp,
                        color = Color(0xFF64748B),
                        modifier = Modifier.padding(top = 4.dp)
                    )

                    Spacer(modifier = Modifier.height(24.dp))

                    // Clock Widget Button
                    val buttonColor = if (viewModel.isClockedIn) Color(0xFFEF4444) else Color(0xFF10B981)
                    val statusText = if (viewModel.isClockedIn) "CLOCK OUT" else "CLOCK IN"

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
                            text = statusText,
                            color = Color.White,
                            fontWeight = FontWeight.Black,
                            fontSize = 14.sp
                        )
                    }

                    Spacer(modifier = Modifier.height(20.dp))

                    if (!viewModel.isClockedIn) {
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
                Text("Log History", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
            }
        }

        if (viewModel.attendanceLogs.isEmpty()) {
            item {
                Text("No logs registered for today.", color = Color(0xFF94A3B8), fontSize = 13.sp)
            }
        } else {
            items(viewModel.attendanceLogs) { log ->
                AttendanceLogRow(log = log)
            }
        }
    }
}

@Composable
fun AttendanceLogRow(log: AttendanceResponse) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White)
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
                Text("In: ${log.clockInAt.substringBefore("T")}", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = Color(0xFF1E293B))
                if (!log.notes.isNullOrEmpty()) {
                    Text(log.notes, fontSize = 11.sp, color = Color(0xFF64748B))
                }
            }
            Box(
                modifier = Modifier
                    .background(
                        color = if (log.clockOutAt != null) Color(0xFFE2E8F0) else Color(0xFFD1FAE5),
                        shape = RoundedCornerShape(6.dp)
                    )
                    .padding(horizontal = 6.dp, vertical = 2.dp)
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
