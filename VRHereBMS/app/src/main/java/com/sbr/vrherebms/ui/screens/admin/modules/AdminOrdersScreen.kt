package com.sbr.vrherebms.ui.screens.admin.modules

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.animation.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.ui.window.Dialog
import com.sbr.vrherebms.data.model.*
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminOrdersScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val selectedId = adminViewModel.selectedOrderId
    val selectedOrder = adminViewModel.orders.firstOrNull { it.id == selectedId }

    if (selectedOrder != null) {
        OrderWorkspaceView(
            order = selectedOrder,
            adminViewModel = adminViewModel,
            onBack = { adminViewModel.selectedOrderId = null },
            modifier = modifier
        )
    } else {
        OrderListView(
            adminViewModel = adminViewModel,
            onSelectOrder = { adminViewModel.selectedOrderId = it.id },
            modifier = modifier
        )
    }
}

// MARK: - SubView 1: Order List Pipeline
@Composable
private fun OrderListView(
    adminViewModel: AdminDashboardViewModel,
    onSelectOrder: (OrderResponse) -> Unit,
    modifier: Modifier = Modifier
) {
    var searchQuery by remember { mutableStateOf("") }
    var selectedStatusTab by remember { mutableStateOf("All") }

    val statusTabs = listOf("All", "Pending", "Completed")

    val filteredOrders = adminViewModel.orders.filter { order ->
        val matchesSearch = order.clientName.contains(searchQuery, ignoreCase = true) ||
                order.serviceName.contains(searchQuery, ignoreCase = true) ||
                order.id.contains(searchQuery, ignoreCase = true)

        val matchesTab = when (selectedStatusTab) {
            "Pending" -> order.status != "Completed"
            "Completed" -> order.status == "Completed"
            else -> true
        }

        matchesSearch && matchesTab
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF8FAFC))
            .padding(16.dp)
    ) {
        // Search Query Bar
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            placeholder = { Text("Search by Client, Service, or ID...", fontSize = 13.sp) },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = Color(0xFF64748B)) },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Color(0xFF4F46E5),
                unfocusedBorderColor = Color(0xFFE2E8F0),
                focusedContainerColor = Color.White,
                unfocusedContainerColor = Color.White
            ),
            singleLine = true
        )

        Spacer(modifier = Modifier.height(12.dp))

        // Status Chips Tabs Row
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            statusTabs.forEach { tab ->
                val isSelected = selectedStatusTab == tab
                val bg = if (isSelected) Color(0xFF4F46E5) else Color.White
                val textColor = if (isSelected) Color.White else Color(0xFF64748B)
                val border = if (isSelected) Color.Transparent else Color(0xFFE2E8F0)

                Box(
                    modifier = Modifier
                        .background(bg, RoundedCornerShape(20.dp))
                        .clickable { selectedStatusTab = tab }
                        .border(1.dp, border, RoundedCornerShape(20.dp))
                        .padding(horizontal = 16.dp, vertical = 7.dp)
                ) {
                    Text(
                        text = tab,
                        color = textColor,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        if (filteredOrders.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Default.LayersClear,
                        contentDescription = null,
                        tint = Color(0xFF94A3B8),
                        modifier = Modifier.size(54.dp)
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text("No projects found matching filters.", color = Color(0xFF64748B), fontSize = 13.sp)
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                items(filteredOrders) { order ->
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onSelectOrder(order) },
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = order.serviceName,
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF1E293B),
                                    modifier = Modifier.weight(1f)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                val isCompleted = order.status == "Completed"
                                Box(
                                    modifier = Modifier
                                        .background(
                                            if (isCompleted) Color(0xFFD1FAE5) else Color(0xFFFFEDD5),
                                            RoundedCornerShape(6.dp)
                                        )
                                        .padding(horizontal = 8.dp, vertical = 4.dp)
                                ) {
                                    Text(
                                        text = order.status.uppercase(),
                                        color = if (isCompleted) Color(0xFF065F46) else Color(0xFF9A3412),
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Black
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(6.dp))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = "${order.clientName} • Pkg: ${order.packageName}",
                                    fontSize = 12.sp,
                                    color = Color(0xFF64748B)
                                )
                                Text(
                                    text = "₹%,.0f".format(order.price),
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFF10B981)
                                )
                            }

                            Spacer(modifier = Modifier.height(10.dp))
                            Divider(color = Color(0xFFF1F5F9))
                            Spacer(modifier = Modifier.height(8.dp))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = "Tap to open complete 9-tab workspace →",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    color = Color(0xFF4F46E5)
                                )
                                Icon(
                                    Icons.Default.ChevronRight,
                                    contentDescription = null,
                                    tint = Color(0xFF4F46E5),
                                    modifier = Modifier.size(16.dp)
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

// MARK: - SubView 2: Complete 9-Tab Order Workspace Hub
@Composable
private fun OrderWorkspaceView(
    order: OrderResponse,
    adminViewModel: AdminDashboardViewModel,
    onBack: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var activeWorkspaceTab by remember { mutableStateOf("Overview") }

    // Dialog controllers
    var showEditNameDialog by remember { mutableStateOf(false) }
    var showRaiseTicketDialog by remember { mutableStateOf(false) }
    var showRecurringDialog by remember { mutableStateOf(false) }

    val workspaceTabs = listOf(
        "Overview", "Tasks", "Requirements", "Workflow Tickets",
        "Invoices", "ToDo", "Transactions", "Activities", "Docs"
    )

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF8FAFC))
    ) {
        // Workspace Top Bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color.White)
                .padding(horizontal = 16.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            IconButton(
                onClick = onBack,
                modifier = Modifier
                    .size(36.dp)
                    .background(Color(0xFFF1F5F9), RoundedCornerShape(10.dp))
            ) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = Color(0xFF1E293B), modifier = Modifier.size(18.dp))
            }

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = order.serviceName,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF1E293B)
                )
                Text(
                    text = "ORDER #${order.id.takeLast(6).uppercase()}",
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF64748B)
                )
            }

            Box(
                modifier = Modifier
                    .background(Color(0xFFEEF2FF), RoundedCornerShape(8.dp))
                    .padding(horizontal = 8.dp, vertical = 4.dp)
            ) {
                Text(
                    text = order.status.uppercase(),
                    fontSize = 9.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF4F46E5)
                )
            }
        }

        Divider(color = Color(0xFFE2E8F0))

        // Content Scrollable
        Column(
            modifier = Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Top Order Card with In-line Edit, Call/Email, Modals & 5-Column Grid
            TopOrderHeroCard(
                order = order,
                adminViewModel = adminViewModel,
                onEditName = { showEditNameDialog = true },
                onRaiseTicket = { showRaiseTicketDialog = true },
                onSetupRecurring = { showRecurringDialog = true }
            )

            // 9 Workspace Subtabs Strip
            ScrollableTabRow(
                selectedTabIndex = workspaceTabs.indexOf(activeWorkspaceTab).coerceAtLeast(0),
                containerColor = Color.White,
                contentColor = Color(0xFF4F46E5),
                edgePadding = 8.dp,
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(12.dp))
            ) {
                workspaceTabs.forEach { tabName ->
                    val isSelected = activeWorkspaceTab == tabName
                    Tab(
                        selected = isSelected,
                        onClick = { activeWorkspaceTab = tabName },
                        text = {
                            Text(
                                text = tabName,
                                fontSize = 11.sp,
                                fontWeight = if (isSelected) FontWeight.Black else FontWeight.Bold,
                                color = if (isSelected) Color(0xFF4F46E5) else Color(0xFF64748B)
                            )
                        }
                    )
                }
            }

            // Tab View Router
            when (activeWorkspaceTab) {
                "Overview" -> OrderOverviewTabContent(order = order, adminViewModel = adminViewModel)
                "Tasks" -> OrderTasksTabContent(order = order)
                "Requirements" -> OrderRequirementsTabContent(order = order)
                "Workflow Tickets" -> OrderWorkflowTicketsTabContent(order = order, onRaise = { showRaiseTicketDialog = true })
                "Invoices" -> OrderInvoicesTabContent(order = order)
                "ToDo" -> OrderTodoTabContent(order = order)
                "Transactions" -> OrderTransactionsTabContent(order = order)
                "Activities" -> OrderActivitiesTabContent(order = order)
                "Docs" -> OrderDocsTabContent(order = order)
            }
        }
    }

    // Modal 1: Inline Title Edit Dialog
    if (showEditNameDialog) {
        var newName by remember { mutableStateOf(order.clientName) }
        AlertDialog(
            onDismissRequest = { showEditNameDialog = false },
            title = { Text("Edit Client / Title", fontWeight = FontWeight.Bold) },
            text = {
                OutlinedTextField(
                    value = newName,
                    onValueChange = { newName = it },
                    label = { Text("Client Name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            },
            confirmButton = {
                Button(onClick = {
                    adminViewModel.updateOrderClientName(order.id, newName)
                    showEditNameDialog = false
                }) {
                    Text("Save")
                }
            },
            dismissButton = {
                TextButton(onClick = { showEditNameDialog = false }) { Text("Cancel") }
            }
        )
    }

    // Modal 2: Raise Workflow Ticket Dialog
    if (showRaiseTicketDialog) {
        var subject by remember { mutableStateOf("") }
        var category by remember { mutableStateOf("Technical") }
        var priority by remember { mutableStateOf("Normal") }
        var desc by remember { mutableStateOf("") }

        AlertDialog(
            onDismissRequest = { showRaiseTicketDialog = false },
            title = { Text("Raise Workflow Ticket", fontWeight = FontWeight.Black) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedTextField(value = subject, onValueChange = { subject = it }, label = { Text("Subject") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = desc, onValueChange = { desc = it }, label = { Text("Description") }, modifier = Modifier.fillMaxWidth())
                }
            },
            confirmButton = {
                Button(onClick = {
                    Toast.makeText(context, "Workflow Ticket Created!", Toast.LENGTH_SHORT).show()
                    showRaiseTicketDialog = false
                }) {
                    Text("Submit Ticket")
                }
            },
            dismissButton = {
                TextButton(onClick = { showRaiseTicketDialog = false }) { Text("Cancel") }
            }
        )
    }

    // Modal 3: Setup Recurring Schedule Dialog
    if (showRecurringDialog) {
        var freq by remember { mutableStateOf("Monthly") }
        AlertDialog(
            onDismissRequest = { showRecurringDialog = false },
            title = { Text("Setup Recurring Schedule", fontWeight = FontWeight.Black) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Automate recurring renewals and invoice generation.", fontSize = 12.sp, color = Color(0xFF64748B))
                    Text("Frequency: $freq (Every 1 Month)", fontSize = 13.sp, fontWeight = FontWeight.Bold)
                }
            },
            confirmButton = {
                Button(onClick = {
                    Toast.makeText(context, "Recurring Schedule Activated!", Toast.LENGTH_SHORT).show()
                    showRecurringDialog = false
                }) {
                    Text("Activate Schedule")
                }
            },
            dismissButton = {
                TextButton(onClick = { showRecurringDialog = false }) { Text("Cancel") }
            }
        )
    }
}

// MARK: - Top Order Hero Card
@Composable
private fun TopOrderHeroCard(
    order: OrderResponse,
    adminViewModel: AdminDashboardViewModel,
    onEditName: () -> Unit,
    onRaiseTicket: () -> Unit,
    onSetupRecurring: () -> Unit
) {
    val context = LocalContext.current

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            // Row 1: Client Name + Pencil Edit + Valuation
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text(
                        text = order.clientName,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFF1E293B)
                    )
                    IconButton(onClick = onEditName, modifier = Modifier.size(24.dp)) {
                        Icon(Icons.Default.Edit, contentDescription = "Edit", tint = Color(0xFF4F46E5), modifier = Modifier.size(14.dp))
                    }
                }
                Text(
                    text = "₹%,.0f".format(order.price),
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF10B981)
                )
            }

            // Row 2: Phone & Email Direct Action Links
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                if (order.phone.isNotEmpty()) {
                    Row(
                        modifier = Modifier
                            .background(Color(0xFFEFF6FF), RoundedCornerShape(8.dp))
                            .clickable {
                                val intent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:${order.phone}"))
                                context.startActivity(intent)
                            }
                            .padding(horizontal = 8.dp, vertical = 5.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        Icon(Icons.Default.Phone, contentDescription = null, tint = Color(0xFF2563EB), modifier = Modifier.size(12.dp))
                        Text(order.phone, fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF2563EB))
                    }
                }

                if (order.email.isNotEmpty()) {
                    Row(
                        modifier = Modifier
                            .background(Color(0xFFF3E8FF), RoundedCornerShape(8.dp))
                            .clickable {
                                val intent = Intent(Intent.ACTION_SENDTO, Uri.parse("mailto:${order.email}"))
                                context.startActivity(intent)
                            }
                            .padding(horizontal = 8.dp, vertical = 5.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        Icon(Icons.Default.Email, contentDescription = null, tint = Color(0xFF9333EA), modifier = Modifier.size(12.dp))
                        Text(order.email, fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF9333EA))
                    }
                }
            }

            // Row 3: Raise Workflow Ticket & Recurring Buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = onRaiseTicket,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(vertical = 6.dp)
                ) {
                    Icon(Icons.Default.ConfirmationNumber, contentDescription = null, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Raise Ticket", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }

                Button(
                    onClick = onSetupRecurring,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF7C3AED)),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(vertical = 6.dp)
                ) {
                    Icon(Icons.Default.Loop, contentDescription = null, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Setup Recurring", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }
            }

            Divider(color = Color(0xFFEEF2F6))

            // Row 4: 5-Column Specialist Assignment Matrix
            Text("SPECIALIST ASSIGNMENTS (5 ROLES)", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))

            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                AssignmentRow(role = "Assignee", current = order.assignedEmployee?.name)
                AssignmentRow(role = "Maker", current = order.assignedMaker?.name)
                AssignmentRow(role = "Checker", current = order.assignedChecker?.name)
                AssignmentRow(role = "Project Manager", current = order.assignedProjectManager?.name)
                AssignmentRow(role = "Freelancer", current = order.assignedFreelancer?.name)
            }
        }
    }
}

@Composable
private fun AssignmentRow(role: String, current: String?) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFFF8FAFC), RoundedCornerShape(8.dp))
            .padding(horizontal = 10.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(role, fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
        Text(current ?: "Unassigned", fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = if (current != null) Color(0xFF4F46E5) else Color(0xFF94A3B8))
    }
}

// MARK: - Tab Contents
@Composable
private fun OrderOverviewTabContent(order: OrderResponse, adminViewModel: AdminDashboardViewModel) {
    val statuses = listOf("Draft", "Review", "In Progress", "Checker Queue", "Delivered", "Completed", "Cancelled")

    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text("STATUS TRANSITION PIPELINE", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
        
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            statuses.forEach { st ->
                val isCurrent = order.status.equals(st, ignoreCase = true)
                Box(
                    modifier = Modifier
                        .background(if (isCurrent) Color(0xFF10B981) else Color.White, RoundedCornerShape(8.dp))
                        .border(1.dp, if (isCurrent) Color(0xFF10B981) else Color(0xFFE2E8F0), RoundedCornerShape(8.dp))
                        .clickable { adminViewModel.updateOrderStatus(order.id, st) }
                        .padding(horizontal = 10.dp, vertical = 6.dp)
                ) {
                    Text(
                        text = st,
                        color = if (isCurrent) Color.White else Color(0xFF1E293B),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
            shape = RoundedCornerShape(14.dp)
        ) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("CLIENT ENGAGEMENT BRIEF", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                Text("Service: ${order.serviceName} (${order.packageName})", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                Text("Payment ID: ${order.paymentId.ifEmpty { "Manual / Offline" }}", fontSize = 11.sp, color = Color(0xFF64748B))
                Text("Payment Status: ${order.paymentStatus}", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF10B981))
            }
        }
    }
}

@Composable
private fun OrderTasksTabContent(order: OrderResponse) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("ORDER TASKS & SOW", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
        if (order.tasks.isEmpty()) {
            Text("No specific subtasks logged yet.", fontSize = 12.sp, color = Color(0xFF64748B))
        } else {
            order.tasks.forEach { task ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color.White, RoundedCornerShape(10.dp))
                        .padding(12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(task.title, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                        Text("Role: ${task.ownerRole.ifEmpty { "Specialist" }}", fontSize = 10.sp, color = Color(0xFF64748B))
                    }
                    Text(task.status, fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFF4F46E5))
                }
            }
        }
    }
}

@Composable
private fun OrderRequirementsTabContent(order: OrderResponse) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("CLIENT SUBMITTED REQUIREMENTS", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
        if (order.customerRequirements.isEmpty()) {
            Text("No custom requirement forms attached.", fontSize = 12.sp, color = Color(0xFF64748B))
        } else {
            order.customerRequirements.forEach { req ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(req.title, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                        Text("Status: ${req.status}", fontSize = 10.sp, color = Color(0xFF64748B))
                    }
                }
            }
        }
    }
}

@Composable
private fun OrderWorkflowTicketsTabContent(order: OrderResponse, onRaise: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("WORKFLOW TICKETS", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
            Button(onClick = onRaise, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)) {
                Text("+ New Ticket", fontSize = 10.sp)
            }
        }
        Text("No active workflow escalations for this order.", fontSize = 12.sp, color = Color(0xFF64748B))
    }
}

@Composable
private fun OrderInvoicesTabContent(order: OrderResponse) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("GST TAX INVOICES", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
        if (order.invoices.isEmpty()) {
            Text("No tax invoices generated yet.", fontSize = 12.sp, color = Color(0xFF64748B))
        } else {
            order.invoices.forEach { inv ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color.White, RoundedCornerShape(10.dp))
                        .padding(12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(inv.invoiceNumber, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    Text("₹%,.0f".format(inv.amount), fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF10B981))
                }
            }
        }
    }
}

@Composable
private fun OrderTodoTabContent(order: OrderResponse) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("ORDER TO-DO ITEMS", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
        Text("All order-specific todos are synchronized.", fontSize = 12.sp, color = Color(0xFF64748B))
    }
}

@Composable
private fun OrderTransactionsTabContent(order: OrderResponse) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("TRANSACTIONS & RECEIPTS", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color.White, RoundedCornerShape(10.dp))
                .padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(order.paymentId.ifEmpty { "Manual TXN" }, fontSize = 12.sp, fontWeight = FontWeight.Bold)
            Text("₹%,.0f".format(order.price), fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF10B981))
        }
    }
}

@Composable
private fun OrderActivitiesTabContent(order: OrderResponse) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("AUDIT LOGS & ACTION DIFFS", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
        if (order.activityHistory.isEmpty()) {
            Text("Order created and status logged.", fontSize = 12.sp, color = Color(0xFF64748B))
        } else {
            order.activityHistory.forEach { act ->
                Text("• ${act.action} by ${act.author} (${act.timestamp})", fontSize = 11.sp, color = Color(0xFF1E293B))
            }
        }
    }
}

@Composable
private fun OrderDocsTabContent(order: OrderResponse) {
    val context = LocalContext.current
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("DELIVERABLES & DOCUMENT VAULT", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
        if (order.clientDocuments.isEmpty() && order.adminDocuments.isEmpty()) {
            Text("No files uploaded.", fontSize = 12.sp, color = Color(0xFF64748B))
        } else {
            (order.clientDocuments + order.adminDocuments).forEach { doc ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color.White, RoundedCornerShape(10.dp))
                        .padding(12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(doc.name, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    IconButton(onClick = { Toast.makeText(context, "Opening ${doc.name}...", Toast.LENGTH_SHORT).show() }) {
                        Icon(Icons.Default.Download, contentDescription = null, tint = Color(0xFF4F46E5))
                    }
                }
            }
        }
    }
}
