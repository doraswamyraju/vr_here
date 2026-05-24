package com.sbr.vrherebms.ui.screens.employee

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.OrderResponse
import com.sbr.vrherebms.viewmodel.EmployeeDashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EmployeeQueueTab(
    viewModel: EmployeeDashboardViewModel,
    selectedOrder: OrderResponse?,
    onSelectOrder: (OrderResponse?) -> Unit
) {
    val orders = viewModel.assignedOrders

    if (selectedOrder != null) {
        // Detailed Order View
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.clickable { onSelectOrder(null) }
                ) {
                    Icon(Icons.Default.ArrowBack, contentDescription = null, tint = Color(0xFF64748B))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Back to Queue", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF64748B))
                }
            }

            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            selectedOrder.serviceName,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Black,
                            color = Color(0xFF1E293B)
                        )
                        Text(
                            "Client: ${selectedOrder.clientName} (${selectedOrder.email})",
                            fontSize = 13.sp,
                            color = Color(0xFF64748B)
                        )
                        Text(
                            "Status: ${selectedOrder.status}",
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF0EA5E9)
                        )
                    }
                }
            }

            // Document checklist
            item {
                Text(
                    "Client Uploaded Documents",
                    fontWeight = FontWeight.Black,
                    fontSize = 15.sp,
                    color = Color(0xFF1E293B),
                    modifier = Modifier.padding(top = 8.dp)
                )
            }

            if (selectedOrder.clientDocuments.isEmpty()) {
                item {
                    Text("No documents uploaded by client yet.", fontSize = 12.sp, color = Color(0xFF64748B))
                }
            } else {
                items(selectedOrder.clientDocuments) { doc ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp),
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
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Description, contentDescription = null, tint = Color(0xFF64748B))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    doc.name,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 12.sp,
                                    color = Color(0xFF1E293B)
                                )
                            }
                            Box(
                                modifier = Modifier
                                    .background(Color(0xFFECFDF5), RoundedCornerShape(8.dp))
                                    .padding(horizontal = 8.dp, vertical = 4.dp)
                            ) {
                                Text(
                                    "Uploaded",
                                    color = Color(0xFF065F46),
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Black
                                )
                            }
                        }
                    }
                }
            }

            // Tasks List
            item {
                Text(
                    "Project Task Tracker",
                    fontWeight = FontWeight.Black,
                    fontSize = 15.sp,
                    color = Color(0xFF1E293B),
                    modifier = Modifier.padding(top = 8.dp)
                )
            }

            if (selectedOrder.tasks.isEmpty()) {
                item {
                    Text("No operational steps assigned yet.", fontSize = 12.sp, color = Color(0xFF64748B))
                }
            } else {
                items(selectedOrder.tasks) { task ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(
                                horizontalArrangement = Arrangement.SpaceBetween,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(
                                    task.title,
                                    fontWeight = FontWeight.Black,
                                    fontSize = 13.sp,
                                    color = Color(0xFF1E293B)
                                )
                                Box(
                                    modifier = Modifier
                                        .background(
                                            when (task.status) {
                                                "Completed" -> Color(0xFFD1FAE5)
                                                "In Progress" -> Color(0xFFFEF3C7)
                                                else -> Color(0xFFF1F5F9)
                                            },
                                            RoundedCornerShape(6.dp)
                                        )
                                        .padding(horizontal = 6.dp, vertical = 2.dp)
                                ) {
                                    Text(
                                        task.status,
                                        color = when (task.status) {
                                            "Completed" -> Color(0xFF065F46)
                                            "In Progress" -> Color(0xFF92400E)
                                            else -> Color(0xFF64748B)
                                        },
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Black
                                    )
                                }
                            }
                            if (task.description.isNotEmpty()) {
                                Text(
                                    task.description,
                                    fontSize = 11.sp,
                                    color = Color(0xFF64748B),
                                    modifier = Modifier.padding(top = 4.dp)
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
    } else {
        // Queue List View
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        "Operations Queue",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFF1E293B)
                    )
                    Text(
                        "View all ongoing assignments and active compliance filings.",
                        fontSize = 12.sp,
                        color = Color(0xFF64748B)
                    )
                }
            }

            if (orders.isEmpty()) {
                item {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 40.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text("No projects currently assigned to you.", color = Color(0xFF64748B))
                    }
                }
            } else {
                items(orders) { order ->
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onSelectOrder(order) },
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Row(
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        order.clientName,
                                        fontWeight = FontWeight.Black,
                                        fontSize = 15.sp,
                                        color = Color(0xFF0F172A)
                                    )
                                    Text(
                                        order.serviceName,
                                        fontSize = 11.sp,
                                        color = Color(0xFF64748B),
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(top = 2.dp)
                                    )
                                }
                                Box(
                                    modifier = Modifier
                                        .background(Color(0xFFE0E7FF), RoundedCornerShape(8.dp))
                                    .padding(horizontal = 8.dp, vertical = 4.dp)
                                ) {
                                    Text(
                                        "Manage",
                                        color = Color(0xFF3730A3),
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Black
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
}
