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
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.EmployeeDashboardViewModel

@Composable
fun EmployeeOverviewTab(
    viewModel: EmployeeDashboardViewModel,
    userName: String,
    onSelectTab: (String) -> Unit
) {
    val orders = viewModel.assignedOrders
    val isClockedIn = viewModel.isClockedIn

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Welcome Greeting Banner
        item {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        brush = Brush.linearGradient(listOf(Color(0xFF0F172A), Color(0xFF1E293B))),
                        shape = RoundedCornerShape(24.dp)
                    )
                    .padding(20.dp)
            ) {
                Column {
                    Text(
                        "Hello, ${userName.split(" ").firstOrNull() ?: userName}",
                        color = Color.White,
                        fontWeight = FontWeight.Black,
                        fontSize = 20.sp
                    )
                    Text(
                        "Manage steps and verify document compliance for registered clients.",
                        color = Color(0xFF94A3B8),
                        fontSize = 12.sp,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
            }
        }

        // Attendance Quick-Widget
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .background(
                                    if (isClockedIn) Color(0xFFECFDF5) else Color(0xFFFEF2F2),
                                    CircleShape
                                ),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = if (isClockedIn) Icons.Default.CheckCircle else Icons.Default.Cancel,
                                contentDescription = null,
                                tint = if (isClockedIn) Color(0xFF10B981) else Color(0xFFEF4444)
                            )
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text(
                                if (isClockedIn) "Clocked In & Active" else "Clocked Out",
                                fontWeight = FontWeight.Black,
                                fontSize = 14.sp,
                                color = Color(0xFF1E293B)
                            )
                            Text(
                                if (isClockedIn) "Timer active" else "Not working currently",
                                fontSize = 11.sp,
                                color = Color(0xFF64748B)
                            )
                        }
                    }
                    Button(
                        onClick = { onSelectTab("Attendance") },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (isClockedIn) Color(0xFFEF4444) else Color(0xFF10B981)
                        ),
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        Text(
                            if (isClockedIn) "Clock Out" else "Clock In",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }

        // Stats grid
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                EmployeeOverviewStatCard(
                    modifier = Modifier.weight(1f),
                    title = "Assigned Projects",
                    value = orders.size.toString(),
                    icon = Icons.Default.FolderOpen,
                    color = Color(0xFF0EA5E9)
                )
                EmployeeOverviewStatCard(
                    modifier = Modifier.weight(1f),
                    title = "Pending Docs",
                    value = orders.filter { it.status == "Pending Documents" }.size.toString(),
                    icon = Icons.Default.PendingActions,
                    color = Color(0xFFF59E0B)
                )
            }
        }

        // Recent work list title
        item {
            Text(
                "My Work Queue",
                fontWeight = FontWeight.Black,
                fontSize = 16.sp,
                color = Color(0xFF1E293B),
                modifier = Modifier.padding(top = 8.dp)
            )
        }

        if (orders.isEmpty()) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 32.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text("No projects currently assigned to you.", color = Color(0xFF64748B), fontSize = 12.sp)
                }
            }
        } else {
            items(orders) { order ->
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onSelectTab("Queue") },
                    shape = RoundedCornerShape(18.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
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
                                Text(
                                    order.serviceName,
                                    fontWeight = FontWeight.Black,
                                    fontSize = 14.sp,
                                    color = Color(0xFF1E293B)
                                )
                                Text(
                                    "Client: ${order.clientName}",
                                    fontSize = 11.sp,
                                    color = Color(0xFF64748B)
                                )
                            }
                        }
                        Divider(modifier = Modifier.padding(vertical = 12.dp), color = Color(0xFFF1F5F9))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                "Milestone: ${order.status}",
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF64748B)
                            )
                            Box(
                                modifier = Modifier
                                    .background(Color(0xFFE0E7FF), RoundedCornerShape(6.dp))
                                    .padding(horizontal = 8.dp, vertical = 4.dp)
                            ) {
                                Text(
                                    "View Details",
                                    fontSize = 8.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF3730A3)
                                )
                            }
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
