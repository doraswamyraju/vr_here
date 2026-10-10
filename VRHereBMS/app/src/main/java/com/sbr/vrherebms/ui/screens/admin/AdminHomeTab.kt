package com.sbr.vrherebms.ui.screens.admin

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.OrderResponse
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel
import java.text.NumberFormat
import java.util.Locale

@Composable
fun AdminHomeTab(
    adminViewModel: AdminDashboardViewModel,
    userName: String,
    onOpenNewOrder: () -> Unit,
    onOpenNewTodo: () -> Unit,
    onNavigate: (String) -> Unit
) {
    val textDark = Color(0xFF1E293B)
    val textMuted = Color(0xFF64748B)
    val borderLight = Color(0xFFF1F5F9)
    val primaryRed = Color(0xFFE11D48)

    // Helper status color matching web/iOS palette
    fun getStatusColor(status: String): Color {
        val s = status.lowercase()
        return when {
            s.contains("complete") || s.contains("verified") || s.contains("approved") -> Color(0xFF10B981) // Green
            s.contains("pending doc") || s.contains("clarification") -> Color(0xFFF97316) // Orange
            s.contains("in progress") || s.contains("processing") || s.contains("assigned") -> Color(0xFF3B82F6) // Blue
            else -> Color(0xFF6366F1) // Indigo
        }
    }

    // Dynamic Calculations
    val orders = adminViewModel.orders
    val totalOrders = orders.size
    val pendingCount = orders.count { it.status != "Completed" }
    val completedCount = orders.count { it.status == "Completed" }
    val totalVal = orders.sumOf { it.price }

    fun formatCurrency(amount: Double): String {
        return NumberFormat.getNumberInstance(Locale.US).format(amount.toLong())
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFFF8FAFC)),
        contentPadding = PaddingValues(bottom = 120.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // MARK: 1. Hero Operations Studio Card (1:1 with iOS/Web)
        item {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
                    .padding(top = 12.dp)
                    .shadow(elevation = 8.dp, shape = RoundedCornerShape(24.dp), ambientColor = Color(0x33000000))
                    .clip(RoundedCornerShape(24.dp))
                    .background(
                        Brush.linearGradient(
                            colors = listOf(
                                Color(0xFF0F172A), // Deep navy
                                Color(0xFF1E1B4B), // Indigo violet
                                Color(0xFF2E1065)  // Royal purple
                            )
                        )
                    )
                    .padding(20.dp)
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "ADMIN COMMAND CENTER (V1.1.8 - POWER TOOLS)",
                        fontSize = 9.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = Color(0xFF38BDF8),
                        letterSpacing = 1.sp
                    )

                    Text(
                        text = "Operations Studio",
                        fontSize = 26.sp,
                        fontWeight = FontWeight.Black,
                        color = Color.White
                    )

                    Text(
                        text = "Service delivery, consultation conversion, and execution status in one place.",
                        fontSize = 13.sp,
                        color = Color.White.copy(alpha = 0.85f),
                        lineHeight = 18.sp,
                        maxLines = 2
                    )

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        // Active Pipeline Chip
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(10.dp))
                                .background(Color.White.copy(alpha = 0.12f))
                                .clickable { onNavigate("Orders") }
                                .padding(horizontal = 14.dp, vertical = 8.dp)
                        ) {
                            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(
                                    text = "ACTIVE PIPELINE",
                                    fontSize = 8.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF38BDF8)
                                )
                                Text(
                                    text = "$pendingCount Projects",
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color.White
                                )
                            }
                        }

                        // Total Value Chip
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(10.dp))
                                .background(Color.White.copy(alpha = 0.12f))
                                .clickable { onNavigate("Finance") }
                                .padding(horizontal = 14.dp, vertical = 8.dp)
                        ) {
                            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(
                                    text = "TOTAL VALUE",
                                    fontSize = 8.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF10B981)
                                )
                                Text(
                                    text = "Rs. ${formatCurrency(totalVal)}",
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color.White
                                )
                            }
                        }
                    }
                }
            }
        }

        // MARK: 2. Quick Action Grid (4 Buttons 1:1 Horizontal Row Layout)
        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                QuickActionButton(
                    modifier = Modifier.weight(1f),
                    title = "NEW ORDER",
                    icon = Icons.Default.Add,
                    bgColor = Color(0xFF10B981), // Emerald
                    onClick = onOpenNewOrder
                )

                QuickActionButton(
                    modifier = Modifier.weight(1f),
                    title = "ADD TO-DO",
                    icon = Icons.Default.Check,
                    bgColor = Color(0xFFF59E0B), // Amber
                    onClick = onOpenNewTodo
                )

                QuickActionButton(
                    modifier = Modifier.weight(1f),
                    title = "ORDERS",
                    icon = Icons.Default.Layers,
                    bgColor = Color(0xFF6366F1), // Indigo
                    onClick = {
                        adminViewModel.selectedOrderId = null
                        onNavigate("Orders")
                    }
                )

                QuickActionButton(
                    modifier = Modifier.weight(1f),
                    title = "REFRESH",
                    icon = Icons.Default.Sync,
                    bgColor = Color(0xFF475569), // Slate
                    onClick = { adminViewModel.syncDashboardData() }
                )
            }
        }

        // MARK: 3. Interactive KPI Metric Cards (2x2 Grid 1:1 with Web/iOS)
        item {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    InteractiveStatCard(
                        modifier = Modifier.weight(1f),
                        label = "TOTAL ORDERS",
                        value = totalOrders.toString(),
                        icon = Icons.Default.Layers,
                        color = Color(0xFF3B82F6),
                        onClick = {
                            adminViewModel.selectedOrderId = null
                            onNavigate("Orders")
                        }
                    )

                    InteractiveStatCard(
                        modifier = Modifier.weight(1f),
                        label = "PENDING",
                        value = pendingCount.toString(),
                        icon = Icons.Default.Schedule,
                        color = Color(0xFFEA580C),
                        onClick = {
                            adminViewModel.selectedOrderId = null
                            onNavigate("Orders")
                        }
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    InteractiveStatCard(
                        modifier = Modifier.weight(1f),
                        label = "COMPLETED",
                        value = completedCount.toString(),
                        icon = Icons.Default.CheckCircle,
                        color = Color(0xFF10B981),
                        onClick = {
                            adminViewModel.selectedOrderId = null
                            onNavigate("Orders")
                        }
                    )

                    InteractiveStatCard(
                        modifier = Modifier.weight(1f),
                        label = "ORDER VALUE",
                        value = "Rs. ${formatCurrency(totalVal)}",
                        icon = Icons.Default.AccountBalanceWallet,
                        color = Color(0xFF6366F1),
                        onClick = {
                            adminViewModel.selectedOrderId = null
                            onNavigate("Orders")
                        }
                    )
                }
            }
        }

        // MARK: 4. Latest Work Updates (1:1 with Web/iOS)
        item {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, borderLight),
                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "LATEST WORK UPDATES",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Black,
                            color = textDark
                        )
                        Text(
                            text = "View All",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = primaryRed,
                            modifier = Modifier.clickable {
                                adminViewModel.selectedOrderId = null
                                onNavigate("Orders")
                            }
                        )
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    val recentOrders = orders.take(5)
                    if (recentOrders.isEmpty()) {
                        Text(
                            text = "No recent orders found",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = textMuted,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 16.dp),
                            textAlign = TextAlign.Center
                        )
                    } else {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            recentOrders.forEachIndexed { index, order ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            adminViewModel.selectedOrderId = order.id
                                            onNavigate("Orders")
                                        }
                                        .padding(vertical = 4.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = order.serviceName.ifEmpty { "Service Delivery" },
                                            fontSize = 13.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = textDark,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                        Spacer(modifier = Modifier.height(2.dp))
                                        Text(
                                            text = order.clientName.ifEmpty { "Guest Client" },
                                            fontSize = 11.sp,
                                            color = textMuted
                                        )
                                    }

                                    Spacer(modifier = Modifier.width(8.dp))

                                    Column(horizontalAlignment = Alignment.End) {
                                        val sColor = getStatusColor(order.status)
                                        Box(
                                            modifier = Modifier
                                                .background(sColor.copy(alpha = 0.12f), RoundedCornerShape(6.dp))
                                                .padding(horizontal = 7.dp, vertical = 3.dp)
                                        ) {
                                            Text(
                                                text = order.status.uppercase(),
                                                fontSize = 8.5.sp,
                                                fontWeight = FontWeight.Black,
                                                color = sColor
                                            )
                                        }
                                        Spacer(modifier = Modifier.height(3.dp))
                                        Text(
                                            text = "Rs. ${formatCurrency(order.price)}",
                                            fontSize = 11.sp,
                                            fontWeight = FontWeight.Black,
                                            color = textDark
                                        )
                                    }
                                }

                                if (index < recentOrders.size - 1) {
                                    Divider(color = borderLight)
                                }
                            }
                        }
                    }
                }
            }
        }

        // MARK: 5. Order Pipeline (Status Breakdown with Progress Bars 1:1)
        item {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, borderLight),
                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                    Text(
                        text = "ORDER PIPELINE",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Black,
                        color = textDark
                    )

                    val statusGrouped = orders.groupBy { it.status }
                        .map { it.key to it.value.size }
                        .sortedByDescending { it.second }

                    if (statusGrouped.isEmpty()) {
                        Text(
                            text = "No pipeline data available",
                            fontSize = 12.sp,
                            color = textMuted,
                            modifier = Modifier.padding(vertical = 10.dp)
                        )
                    } else {
                        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            statusGrouped.forEach { (status, count) ->
                                val ratio = if (totalOrders == 0) 0f else count.toFloat() / totalOrders.toFloat()
                                val sColor = getStatusColor(status)

                                Column(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            adminViewModel.selectedOrderId = null
                                            onNavigate("Orders")
                                        }
                                ) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            text = status.uppercase(),
                                            fontSize = 9.5.sp,
                                            fontWeight = FontWeight.Black,
                                            color = textMuted
                                        )
                                        Text(
                                            text = count.toString(),
                                            fontSize = 12.sp,
                                            fontWeight = FontWeight.Black,
                                            color = textDark
                                        )
                                    }

                                    Spacer(modifier = Modifier.height(6.dp))

                                    Box(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .height(6.dp)
                                            .clip(RoundedCornerShape(3.dp))
                                            .background(borderLight)
                                    ) {
                                        Box(
                                            modifier = Modifier
                                                .fillMaxWidth(fraction = ratio.coerceIn(0.04f, 1f))
                                                .fillMaxHeight()
                                                .clip(RoundedCornerShape(3.dp))
                                                .background(sColor)
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // MARK: 6. System Insights Banner (1:1 with iOS)
        item {
            val avgValue = if (totalOrders == 0) 0.0 else totalVal / totalOrders
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
                    .clip(RoundedCornerShape(18.dp))
                    .background(
                        Brush.linearGradient(
                            colors = listOf(
                                Color(0xFF4F46E5), // Indigo
                                Color(0xFF9333EA)  // Purple
                            )
                        )
                    )
                    .padding(18.dp)
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "SYSTEM INSIGHTS",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Black,
                        color = Color.White
                    )

                    Text(
                        text = "Average project value: Rs. ${formatCurrency(avgValue)}",
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = Color.White.copy(alpha = 0.9f)
                    )

                    Button(
                        onClick = { onNavigate("Reports") },
                        colors = ButtonDefaults.buttonColors(containerColor = Color.White),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 4.dp),
                        contentPadding = PaddingValues(vertical = 8.dp)
                    ) {
                        Text(
                            text = "View Analytics",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Black,
                            color = Color(0xFF4F46E5)
                        )
                    }
                }
            }
        }

        // MARK: 7. Recent Tasks (To-Do Checklist 1:1)
        item {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, borderLight),
                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "RECENT TASKS",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Black,
                            color = textDark
                        )
                        Text(
                            text = "Manage",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = primaryRed,
                            modifier = Modifier.clickable { onNavigate("Todo") }
                        )
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    val recentTodos = adminViewModel.todos.take(4)
                    if (recentTodos.isEmpty()) {
                        Text(
                            text = "No tasks active",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = textMuted,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 16.dp),
                            textAlign = TextAlign.Center
                        )
                    } else {
                        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            recentTodos.forEach { todo ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable { onNavigate("Todo") },
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(8.dp)
                                            .background(
                                                if (todo.status == "Completed") Color(0xFF10B981) else Color(0xFFF59E0B),
                                                CircleShape
                                            )
                                    )

                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = todo.title,
                                            fontSize = 12.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = textDark,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                        Text(
                                            text = todo.assignedTo?.name ?: "UNASSIGNED",
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = textMuted
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // MARK: 8. Top Services Master (1:1)
        item {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, borderLight),
                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "TOP SERVICES",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Black,
                            color = textDark
                        )
                        Text(
                            text = "View Master",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = primaryRed,
                            modifier = Modifier.clickable { onNavigate("Services") }
                        )
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    val topServices = orders.groupBy { it.serviceName }
                        .map { it.key to it.value.size }
                        .sortedByDescending { it.second }
                        .take(4)

                    if (topServices.isEmpty()) {
                        Text(
                            text = "No service metrics available",
                            fontSize = 12.sp,
                            color = textMuted,
                            modifier = Modifier.padding(vertical = 10.dp)
                        )
                    } else {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            topServices.forEachIndexed { index, (name, count) ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 2.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = name.ifEmpty { "General Service" },
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = textDark,
                                        modifier = Modifier.weight(1f),
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Box(
                                        modifier = Modifier
                                            .background(Color(0xFF6366F1).copy(alpha = 0.1f), RoundedCornerShape(6.dp))
                                            .padding(horizontal = 8.dp, vertical = 3.dp)
                                    ) {
                                        Text(
                                            text = count.toString(),
                                            fontSize = 10.sp,
                                            fontWeight = FontWeight.Black,
                                            color = Color(0xFF6366F1)
                                        )
                                    }
                                }

                                if (index < topServices.size - 1) {
                                    Divider(color = borderLight)
                                }
                            }
                        }
                    }
                }
            }
        }

        // MARK: 9. New Users / Community Matrix (1:1 with Web/iOS)
        item {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, borderLight),
                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "NEW USERS",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Black,
                            color = textDark
                        )
                        Text(
                            text = "View All",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = primaryRed,
                            modifier = Modifier.clickable { onNavigate("Users") }
                        )
                    }

                    val userList = adminViewModel.users
                    val totalMembers = userList.size

                    // Avatar Stack
                    Row(
                        horizontalArrangement = Arrangement.spacedBy((-8).dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        userList.take(6).forEach { u ->
                            Box(
                                modifier = Modifier
                                    .size(38.dp)
                                    .clip(CircleShape)
                                    .background(
                                        Brush.linearGradient(
                                            colors = listOf(Color(0xFF6366F1), Color(0xFF3B82F6))
                                        )
                                    ),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    text = u.name.take(1).uppercase(),
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color.White
                                )
                            }
                        }

                        if (totalMembers > 6) {
                            Box(
                                modifier = Modifier
                                    .size(38.dp)
                                    .clip(CircleShape)
                                    .background(Color(0xFFF1F5F9)),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    text = "+${totalMembers - 6}",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Black,
                                    color = textDark
                                )
                            }
                        }
                    }

                    // Total community banner
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .background(Color(0xFFF8FAFC))
                            .clickable { onNavigate("Users") }
                            .padding(12.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text(
                                    text = "TOTAL COMMUNITY",
                                    fontSize = 8.5.sp,
                                    fontWeight = FontWeight.Black,
                                    color = textMuted
                                )
                                Row(horizontalArrangement = Arrangement.spacedBy(4.dp), verticalAlignment = Alignment.Bottom) {
                                    Text(
                                        text = totalMembers.toString(),
                                        fontSize = 18.sp,
                                        fontWeight = FontWeight.Black,
                                        color = textDark
                                    )
                                    Text(
                                        text = "Members",
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Black,
                                        color = Color(0xFF10B981)
                                    )
                                }
                            }
                            Icon(
                                imageVector = Icons.Default.ChevronRight,
                                contentDescription = null,
                                tint = textMuted,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }
                }
            }
        }

        // MARK: 10. Financial Health Breakdown (1:1)
        item {
            val total = orders.sumOf { it.price }
            val paid = orders.filter { it.paymentStatus.equals("paid", ignoreCase = true) }.sumOf { it.price }
            val outstanding = (total - paid).coerceAtLeast(0.0)
            val collectionRate = if (total == 0.0) 0.0 else (paid / total) * 100.0

            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, borderLight),
                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                    Text(
                        text = "FINANCIAL HEALTH",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Black,
                        color = textDark
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text(
                                text = "PAID INFLOW",
                                fontSize = 8.5.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFF10B981)
                            )
                            Text(
                                text = "Rs. ${formatCurrency(paid)}",
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFF10B981)
                            )
                        }

                        Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text(
                                text = "OUTSTANDING",
                                fontSize = 8.5.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFFEF4444)
                            )
                            Text(
                                text = "Rs. ${formatCurrency(outstanding)}",
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFFEF4444)
                            )
                        }
                    }

                    Divider(color = borderLight)

                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                text = "Collection Rate",
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                color = textMuted
                            )
                            Text(
                                text = "%.1f%%".format(collectionRate),
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Black,
                                color = textDark
                            )
                        }

                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(6.dp)
                                .clip(RoundedCornerShape(3.dp))
                                .background(borderLight)
                        ) {
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth(fraction = (collectionRate / 100.0).toFloat().coerceIn(0.04f, 1f))
                                    .fillMaxHeight()
                                    .clip(RoundedCornerShape(3.dp))
                                    .background(Color(0xFF10B981))
                            )
                        }
                    }
                }
            }
        }

        // MARK: 11. Team Workload / Active Specialists (1:1 Dark Slate Banner)
        item {
            val empList = adminViewModel.employees
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
                    .clip(RoundedCornerShape(18.dp))
                    .background(
                        Brush.linearGradient(
                            colors = listOf(
                                Color(0xFF0F172A), // Slate 900
                                Color(0xFF1E293B)  // Slate 800
                            )
                        )
                    )
                    .clickable { onNavigate("Performance") }
                    .padding(18.dp)
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(36.dp)
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(Color.White.copy(alpha = 0.12f)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Groups,
                                    contentDescription = null,
                                    tint = Color(0xFF38BDF8),
                                    modifier = Modifier.size(18.dp)
                                )
                            }

                            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text(
                                    text = "TEAM WORKLOAD",
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color.White
                                )
                                Text(
                                    text = "ACTIVE SPECIALISTS",
                                    fontSize = 8.5.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF38BDF8)
                                )
                            }
                        }

                        Icon(
                            imageVector = Icons.Default.ChevronRight,
                            contentDescription = null,
                            tint = Color.White.copy(alpha = 0.7f),
                            modifier = Modifier.size(16.dp)
                        )
                    }

                    if (empList.isEmpty()) {
                        Text(
                            text = "No specialist workload data",
                            fontSize = 12.sp,
                            color = Color.White.copy(alpha = 0.7f)
                        )
                    } else {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            empList.take(4).forEach { emp ->
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = emp.name,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color.White
                                    )
                                    Box(
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(4.dp))
                                            .background(Color.White.copy(alpha = 0.15f))
                                            .padding(horizontal = 6.dp, vertical = 2.dp)
                                    ) {
                                        Text(
                                            text = emp.role.uppercase(),
                                            fontSize = 8.5.sp,
                                            fontWeight = FontWeight.Black,
                                            color = Color(0xFF38BDF8)
                                        )
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

// 1:1 Quick Action Vertical Button
@Composable
private fun QuickActionButton(
    modifier: Modifier = Modifier,
    title: String,
    icon: ImageVector,
    bgColor: Color,
    onClick: () -> Unit
) {
    Card(
        modifier = modifier
            .clickable { onClick() },
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFF1F5F9)),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 14.dp, horizontal = 4.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .background(bgColor),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = title,
                    tint = Color.White,
                    modifier = Modifier.size(18.dp)
                )
            }

            Text(
                text = title,
                fontSize = 8.5.sp,
                fontWeight = FontWeight.Black,
                color = Color(0xFF475569),
                letterSpacing = 0.5.sp,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

// 1:1 Interactive Stat Card
@Composable
private fun InteractiveStatCard(
    modifier: Modifier = Modifier,
    label: String,
    value: String,
    icon: ImageVector,
    color: Color,
    onClick: () -> Unit
) {
    Card(
        modifier = modifier
            .clickable { onClick() },
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFF1F5F9)),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text(
                    text = label,
                    fontSize = 8.5.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF64748B),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = value,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF1E293B),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            Spacer(modifier = Modifier.width(6.dp))

            Box(
                modifier = Modifier
                    .size(38.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(color.copy(alpha = 0.12f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = label,
                    tint = color,
                    modifier = Modifier.size(18.dp)
                )
            }
        }
    }
}
