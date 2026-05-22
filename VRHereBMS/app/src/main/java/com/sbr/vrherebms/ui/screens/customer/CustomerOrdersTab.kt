package com.sbr.vrherebms.ui.screens.customer

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.BusinessCenter
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel

@Composable
fun CustomerOrdersTab(
    viewModel: CustomerDashboardViewModel,
    selectedOrderId: String,
    onSelectOrderId: (String) -> Unit,
    onSelectTab: (String) -> Unit
) {
    if (selectedOrderId.isNotEmpty()) {
        val order = viewModel.orders.find { it.id == selectedOrderId }
        if (order != null) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp)
                    .verticalScroll(rememberScrollState())
                    .padding(top = 16.dp, bottom = 120.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .scaleOnPress()
                        .clickable { onSelectOrderId("") }
                ) {
                    Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = Color(0xFF6366F1))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Back to Subscriptions", color = Color(0xFF6366F1), fontWeight = FontWeight.Bold, fontSize = 13.sp)
                }

                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Text(order.serviceName, fontSize = 18.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                        Text(order.packageName, fontSize = 12.sp, color = Color(0xFF64748B), modifier = Modifier.padding(top = 2.dp))

                        HorizontalDivider(modifier = Modifier.padding(vertical = 16.dp), color = Color(0xFFF1F5F9))

                        Text("Milestone Tracking Status", fontWeight = FontWeight.Black, fontSize = 14.sp, color = Color(0xFF1E293B))
                        Spacer(modifier = Modifier.height(16.dp))

                        // Timeline steps
                        val milestones = listOf("Pending Documents", "Documents Verified", "Processing at Portal", "Waiting for Clarification", "Completed")
                        val currentMilestoneIndex = milestones.indexOf(order.status)

                        milestones.forEachIndexed { index, milestone ->
                            val isCompleted = index < currentMilestoneIndex
                            val isActive = index == currentMilestoneIndex

                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.padding(vertical = 6.dp)
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(18.dp)
                                        .background(
                                            color = when {
                                                isActive -> Color(0xFF6366F1)
                                                isCompleted -> Color(0xFF10B981)
                                                else -> Color(0xFFCBD5E1)
                                            },
                                            shape = CircleShape
                                        ),
                                    contentAlignment = Alignment.Center
                                ) {
                                    if (isCompleted) {
                                        Icon(Icons.Default.Check, contentDescription = null, tint = Color.White, modifier = Modifier.size(10.dp))
                                    }
                                }
                                Spacer(modifier = Modifier.width(12.dp))
                                Text(
                                    text = milestone,
                                    color = when {
                                        isActive -> Color(0xFF6366F1)
                                        isCompleted -> Color(0xFF10B981)
                                        else -> Color(0xFF64748B)
                                    },
                                    fontWeight = if (isActive) FontWeight.Black else FontWeight.Bold,
                                    fontSize = 13.sp
                                )
                            }
                        }
                    }
                }

                // Requirements Vault in order details
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Text("Vault Requirements", fontSize = 15.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                        Spacer(modifier = Modifier.height(10.dp))

                        if (order.customerRequirements.isEmpty()) {
                            Text("No custom requirements requested for this order.", fontSize = 12.sp, color = Color(0xFF64748B))
                        } else {
                            order.customerRequirements.forEach { req ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 8.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(req.title, fontWeight = FontWeight.Black, fontSize = 12.sp, color = Color(0xFF334155))
                                        Text(req.description, fontSize = 10.sp, color = Color(0xFF64748B))
                                    }
                                    Box(
                                        modifier = Modifier
                                            .background(
                                                color = if (req.status == "Verified") Color(0xFFD1FAE5) else Color(0xFFFEF3C7),
                                                shape = RoundedCornerShape(6.dp)
                                            )
                                            .padding(horizontal = 8.dp, vertical = 4.dp)
                                    ) {
                                        Text(
                                            text = req.status,
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.Black,
                                            color = if (req.status == "Verified") Color(0xFF065F46) else Color(0xFF92400E)
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            onSelectOrderId("")
        }
    } else {
        var selectedCategory by remember { mutableStateOf("All") }
        val categories = listOf("All", "Active", "Completed", "Action Required")

        val filteredOrders = remember(selectedCategory, viewModel.orders) {
            when (selectedCategory) {
                "Active" -> viewModel.orders.filter { it.status != "Completed" }
                "Completed" -> viewModel.orders.filter { it.status == "Completed" }
                "Action Required" -> viewModel.orders.filter {
                    it.status == "Pending Documents" || it.status == "Waiting for Clarification"
                }
                else -> viewModel.orders
            }
        }

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            contentPadding = PaddingValues(top = 16.dp, bottom = 120.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                Column {
                    Text("Your Orders", fontSize = 22.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                    Text("Track the progress of your active requests.", fontSize = 13.sp, color = Color(0xFF64748B), modifier = Modifier.padding(top = 2.dp))
                }
            }

            item {
                LazyRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(categories) { category ->
                        val isSelected = selectedCategory == category
                        Box(
                            modifier = Modifier
                                .background(
                                    color = if (isSelected) Color(0xFF6366F1) else Color(0xFFEEF2F6),
                                    shape = RoundedCornerShape(12.dp)
                                )
                                .clickable { selectedCategory = category }
                                .padding(horizontal = 16.dp, vertical = 8.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = category,
                                color = if (isSelected) Color.White else Color(0xFF475569),
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
            }

            if (filteredOrders.isEmpty()) {
                item {
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 16.dp),
                        shape = RoundedCornerShape(24.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFCBD5E1).copy(alpha = 0.5f))
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(32.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(64.dp)
                                    .background(Color(0xFFEEF2F6), CircleShape),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Default.FolderOpen,
                                    contentDescription = null,
                                    tint = Color(0xFF94A3B8),
                                    modifier = Modifier.size(28.dp)
                                )
                            }
                            Spacer(modifier = Modifier.height(16.dp))
                            Text(
                                text = "No Orders Found",
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFF1E293B)
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = "Looks like you haven't started any projects yet.",
                                fontSize = 12.sp,
                                color = Color(0xFF64748B),
                                textAlign = androidx.compose.ui.text.style.TextAlign.Center
                            )
                            Spacer(modifier = Modifier.height(24.dp))
                            Button(
                                onClick = { onSelectTab("Services") },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6366F1)),
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier.scaleOnPress()
                            ) {
                                Text(
                                    "Browse Services",
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color.White
                                )
                            }
                        }
                    }
                }
            } else {
                items(filteredOrders) { order ->
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .scaleOnPress()
                            .clickable { onSelectOrderId(order.id) },
                        shape = RoundedCornerShape(24.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFF1F5F9))
                    ) {
                        Column(modifier = Modifier.padding(20.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(44.dp)
                                        .background(Color(0xFFEEF2F6), RoundedCornerShape(12.dp)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(Icons.Default.BusinessCenter, contentDescription = null, tint = Color(0xFF6366F1))
                                }
                                Spacer(modifier = Modifier.width(12.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        order.serviceName,
                                        fontSize = 14.sp,
                                        fontWeight = FontWeight.Black,
                                        color = Color(0xFF1E293B)
                                    )
                                    Text(
                                        order.packageName,
                                        fontSize = 11.sp,
                                        color = Color(0xFF64748B)
                                    )
                                }
                                StatusBadgeWidget(status = order.status)
                            }

                            Spacer(modifier = Modifier.height(16.dp))

                            val completeness = getStatusProgress(order.status)
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    "COMPLETENESS",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF94A3B8),
                                    letterSpacing = 0.5.sp
                                )
                                Text(
                                    "$completeness%",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF6366F1)
                                )
                            }
                            Spacer(modifier = Modifier.height(6.dp))
                            LinearProgressIndicator(
                                progress = completeness / 100f,
                                color = Color(0xFF6366F1),
                                trackColor = Color(0xFFEEF2F6),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(6.dp)
                                    .clip(CircleShape)
                            )
                        }
                    }
                }
            }
        }
    }
}
