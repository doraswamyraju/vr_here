package com.sbr.vrherebms.ui.screens

import android.widget.Toast
import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.*
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomerDashboardScreen(
    viewModel: CustomerDashboardViewModel,
    userName: String,
    onLogout: () -> Unit
) {
    var activeTab by remember { mutableStateOf("Home") }
    val context = LocalContext.current

    LaunchedEffect(key1 = true) {
        viewModel.refreshAllData()
        viewModel.eventFlow.collect { event ->
            if (event is CustomerDashboardViewModel.UiEvent.ShowToast) {
                Toast.makeText(context, event.message, Toast.LENGTH_SHORT).show()
            }
        }
    }

    val primaryGradient = listOf(Color(0xFF6366F1), Color(0xFF8B5CF6))

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
                                "Hello, $userName",
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF1E293B)
                            )
                            Text(
                                "Customer Workspace",
                                fontSize = 11.sp,
                                color = Color(0xFF64748B)
                            )
                        }
                    }
                },
                actions = {
                    IconButton(onClick = { viewModel.refreshAllData() }) {
                        Icon(Icons.Default.Refresh, contentDescription = "Refresh")
                    }
                    IconButton(onClick = onLogout) {
                        Icon(Icons.Default.ExitToApp, contentDescription = "Logout", tint = Color(0xFFEF4444))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.White)
            )
        },
        bottomBar = {
            NavigationBar(
                containerColor = Color.White,
                tonalElevation = 8.dp
            ) {
                val navItems = listOf(
                    Triple("Home", Icons.Default.Dashboard, "Home"),
                    Triple("Services", Icons.Default.Work, "Services"),
                    Triple("Orders", Icons.Default.ShoppingBag, "Orders"),
                    Triple("Invoices", Icons.Default.ReceiptLong, "Invoices"),
                    Triple("Support", Icons.Default.HeadsetMic, "Support")
                )

                navItems.forEach { (tabId, icon, label) ->
                    NavigationBarItem(
                        selected = activeTab == tabId,
                        onClick = { activeTab = tabId },
                        icon = { Icon(icon, contentDescription = label) },
                        label = { Text(label, fontSize = 10.sp, fontWeight = FontWeight.Bold) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = Color(0xFF6366F1),
                            selectedTextColor = Color(0xFF6366F1),
                            unselectedIconColor = Color(0xFF94A3B8),
                            unselectedTextColor = Color(0xFF94A3B8),
                            indicatorColor = Color(0xFFEEF2F6)
                        )
                    )
                }
            }
        }
    ) { paddingValues ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .background(Color(0xFFF8FAFC)) // Slate 50
        ) {
            AnimatedContent(
                targetState = activeTab,
                transitionSpec = {
                    fadeIn() togetherWith fadeOut()
                },
                label = "TabTransition"
            ) { targetTab ->
                when (targetTab) {
                    "Home" -> CustomerHomeTab(viewModel, userName, onSelectTab = { activeTab = it })
                    "Services" -> CustomerServicesTab(viewModel)
                    "Orders" -> CustomerOrdersTab(viewModel)
                    "Invoices" -> CustomerInvoicesTab(viewModel)
                    "Support" -> CustomerSupportTab(viewModel)
                }
            }
        }
    }
}

// --- HOME TAB ---
@Composable
fun CustomerHomeTab(
    viewModel: CustomerDashboardViewModel,
    userName: String,
    onSelectTab: (String) -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Welcome Banner Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1E293B))
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Text(
                        "Welcome to VR HERE!",
                        color = Color.White,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Black
                    )
                    Text(
                        "Track operations, manage compliance documentation, and chat with corporate compliance executives natively.",
                        color = Color(0xFF94A3B8),
                        fontSize = 13.sp,
                        modifier = Modifier.padding(top = 6.dp)
                    )
                }
            }
        }

        // Overview Statistics Grid
        item {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                StatCard(
                    modifier = Modifier.weight(1f),
                    title = "Active Orders",
                    value = viewModel.orders.filter { it.status != "Completed" }.size.toString(),
                    icon = Icons.Default.Assignment,
                    color = Color(0xFF6366F1),
                    onClick = { onSelectTab("Orders") }
                )

                StatCard(
                    modifier = Modifier.weight(1f),
                    title = "Total Tickets",
                    value = viewModel.tickets.size.toString(),
                    icon = Icons.Default.HeadsetMic,
                    color = Color(0xFF10B981),
                    onClick = { onSelectTab("Support") }
                )
            }
        }

        // Recent Orders Section
        item {
            Text(
                "My Subscriptions",
                fontSize = 16.sp,
                fontWeight = FontWeight.Black,
                color = Color(0xFF1E293B),
                modifier = Modifier.padding(vertical = 4.dp)
            )
        }

        if (viewModel.orders.isEmpty()) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White)
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(32.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Icon(Icons.Default.ShoppingBag, contentDescription = null, tint = Color(0xFFCBD5E1), modifier = Modifier.size(48.dp))
                            Text("No active service orders.", color = Color(0xFF64748B), fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 8.dp))
                        }
                    }
                }
            }
        } else {
            items(viewModel.orders.take(3)) { order ->
                OrderSummaryRow(order = order, onClick = { onSelectTab("Orders") })
            }
        }
    }
}

@Composable
fun StatCard(
    modifier: Modifier = Modifier,
    title: String,
    value: String,
    icon: ImageVector,
    color: Color,
    onClick: () -> Unit
) {
    Card(
        modifier = modifier.clickable { onClick() },
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .background(color.copy(alpha = 0.1f), CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(20.dp))
                }
            }
            Text(
                value,
                fontSize = 24.sp,
                fontWeight = FontWeight.Black,
                color = Color(0xFF1E293B),
                modifier = Modifier.padding(top = 12.dp)
            )
            Text(
                title,
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                color = Color(0xFF64748B),
                modifier = Modifier.padding(top = 2.dp)
            )
        }
    }
}

@Composable
fun OrderSummaryRow(order: OrderResponse, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() },
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFFE2E8F0))
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
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
                    fontSize = 12.sp,
                    color = Color(0xFF64748B)
                )
            }
            Spacer(modifier = Modifier.width(8.dp))
            Box(
                modifier = Modifier
                    .background(
                        color = when (order.status) {
                            "Completed" -> Color(0xFFD1FAE5)
                            "Waiting for Clarification" -> Color(0xFFFEE2E2)
                            else -> Color(0xFFFEF3C7)
                        },
                        shape = RoundedCornerShape(8.dp)
                    )
                    .padding(horizontal = 8.dp, vertical = 4.dp)
            ) {
                Text(
                    order.status,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Black,
                    color = when (order.status) {
                        "Completed" -> Color(0xFF065F46)
                        "Waiting for Clarification" -> Color(0xFF991B1B)
                        else -> Color(0xFF92400E)
                    }
                )
            }
        }
    }
}

// --- SERVICES TAB ---
@Composable
fun CustomerServicesTab(viewModel: CustomerDashboardViewModel) {
    // Standard mock list replicating React's client service catalog
    val services = listOf(
        "Private Limited Registration" to "Launch your startup with the most credible legal structure. COI, MOA, AOA, PAN & TAN in 7 days.",
        "GST Registration" to "Get your GST number quickly and start filing returns. Essential for tax compliance.",
        "Partnership Firm Registration" to "Ideal for small businesses with multiple owners. Shared deed drafting & PAN setup.",
        "Income Tax Return (ITR)" to "End-to-end ITR filing support for salaried individuals, professionals, and corporate setups."
    )

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Text(
                "Corporate Services Menu",
                fontSize = 20.sp,
                fontWeight = FontWeight.Black,
                color = Color(0xFF1E293B)
            )
            Text(
                "Purchase customized corporate packages and launch legal structures natively.",
                fontSize = 13.sp,
                color = Color(0xFF64748B)
            )
        }

        items(services) { (title, description) ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .background(Color(0xFFEEF2F6), RoundedCornerShape(10.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.VerifiedUser, contentDescription = null, tint = Color(0xFF6366F1))
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            title,
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Black,
                            color = Color(0xFF1E293B)
                        )
                    }
                    Text(
                        description,
                        fontSize = 13.sp,
                        color = Color(0xFF64748B),
                        modifier = Modifier.padding(top = 10.dp)
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Button(
                        onClick = { /* Integrate with Razorpay SDK or raise manual checkout query */ },
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6366F1))
                    ) {
                        Text("Select Package", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    }
                }
            }
        }
    }
}

// --- ORDERS TAB ---
@Composable
fun CustomerOrdersTab(viewModel: CustomerDashboardViewModel) {
    var selectedOrder by remember { mutableStateOf<OrderResponse?>(null) }

    if (selectedOrder != null) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.clickable { selectedOrder = null }
            ) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = Color(0xFF6366F1))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Back to Subscriptions", color = Color(0xFF6366F1), fontWeight = FontWeight.Bold)
            }

            val order = selectedOrder!!

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Text(order.serviceName, fontSize = 18.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                    Text(order.packageName, fontSize = 13.sp, color = Color(0xFF64748B), modifier = Modifier.padding(top = 2.dp))

                    Divider(modifier = Modifier.padding(vertical = 12.dp))

                    Text("Milestone Tracking Status", fontWeight = FontWeight.Black, fontSize = 14.sp, color = Color(0xFF1E293B))

                    Spacer(modifier = Modifier.height(12.dp))

                    // Step Tracker Timeline
                    val milestones = listOf("Pending Documents", "Documents Verified", "Processing at Portal", "Waiting for Clarification", "Completed")
                    milestones.forEachIndexed { index, milestone ->
                        val isActive = order.status == milestone
                        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(vertical = 4.dp)) {
                            Box(
                                modifier = Modifier
                                    .size(16.dp)
                                    .background(
                                        color = if (isActive) Color(0xFF10B981) else Color(0xFFCBD5E1),
                                        shape = CircleShape
                                    )
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                            Text(
                                milestone,
                                color = if (isActive) Color(0xFF10B981) else Color(0xFF64748B),
                                fontWeight = if (isActive) FontWeight.Black else FontWeight.Normal,
                                fontSize = 13.sp
                            )
                        }
                    }
                }
            }

            // Customer Requirements Vault
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Text("Vault Requirements", fontSize = 15.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                    Spacer(modifier = Modifier.height(8.dp))

                    if (order.customerRequirements.isEmpty()) {
                        Text("No specific custom requirements requested for this order.", fontSize = 12.sp, color = Color(0xFF64748B))
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
                                    Text(req.title, fontWeight = FontWeight.Bold, fontSize = 13.sp, color = Color(0xFF1E293B))
                                    Text(req.description, fontSize = 11.sp, color = Color(0xFF64748B))
                                }
                                Box(
                                    modifier = Modifier
                                        .background(
                                            color = when (req.status) {
                                                "Verified" -> Color(0xFFD1FAE5)
                                                else -> Color(0xFFFEF3C7)
                                            },
                                            shape = RoundedCornerShape(6.dp)
                                        )
                                        .padding(horizontal = 6.dp, vertical = 3.dp)
                                ) {
                                    Text(req.status, fontSize = 9.sp, fontWeight = FontWeight.Black, color = if (req.status == "Verified") Color(0xFF065F46) else Color(0xFF92400E))
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item {
                Text("Subscription Orders", fontSize = 20.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                Text("Tap on any active registration to view process mapping timelines.", fontSize = 13.sp, color = Color(0xFF64748B))
            }

            if (viewModel.orders.isEmpty()) {
                item {
                    Box(modifier = Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                        Text("No orders loaded.", color = Color(0xFF64748B))
                    }
                }
            } else {
                items(viewModel.orders) { order ->
                    OrderSummaryRow(order = order, onClick = { selectedOrder = order })
                }
            }
        }
    }
}

// --- INVOICES TAB ---
@Composable
fun CustomerInvoicesTab(viewModel: CustomerDashboardViewModel) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Text("Financial Invoices", fontSize = 20.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
            Text("Verify transaction logs and receipts for your subscription services.", fontSize = 13.sp, color = Color(0xFF64748B))
        }

        if (viewModel.payments.isEmpty()) {
            item {
                Box(modifier = Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                    Text("No billing logs found.", color = Color(0xFF64748B))
                }
            }
        } else {
            items(viewModel.payments) { payment ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .background(Color(0xFFEEF2F6), RoundedCornerShape(10.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.Receipt, contentDescription = null, tint = Color(0xFF10B981))
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(payment.serviceName, fontWeight = FontWeight.Black, fontSize = 14.sp, color = Color(0xFF1E293B))
                            Text("ID: ${payment.paymentId}", fontSize = 11.sp, color = Color(0xFF64748B))
                        }
                        Column(horizontalAlignment = Alignment.End) {
                            Text("₹${payment.amount}", fontWeight = FontWeight.Black, fontSize = 14.sp, color = Color(0xFF1E293B))
                            Box(
                                modifier = Modifier
                                    .padding(top = 4.dp)
                                    .background(Color(0xFFD1FAE5), RoundedCornerShape(6.dp))
                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                            ) {
                                Text("Paid", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF065F46))
                            }
                        }
                    }
                }
            }
        }
    }
}

// --- SUPPORT TAB ---
@Composable
fun CustomerSupportTab(viewModel: CustomerDashboardViewModel) {
    var isNewTicketOpen by remember { mutableStateOf(false) }

    if (isNewTicketOpen) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(20.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.clickable { isNewTicketOpen = false }
            ) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = Color(0xFF6366F1))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Back to Tickets", color = Color(0xFF6366F1), fontWeight = FontWeight.Bold)
            }

            Text("Raise Support Ticket", fontSize = 20.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))

            OutlinedTextField(
                value = viewModel.ticketSubject,
                onValueChange = { viewModel.ticketSubject = it },
                label = { Text("Subject") },
                singleLine = true,
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            )

            OutlinedTextField(
                value = viewModel.ticketDescription,
                onValueChange = { viewModel.ticketDescription = it },
                label = { Text("Query Description") },
                minLines = 4,
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            )

            Button(
                onClick = {
                    viewModel.createSupportTicket()
                    isNewTicketOpen = false
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp),
                shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6366F1))
            ) {
                Text("Submit Ticket", fontWeight = FontWeight.Bold)
            }
        }
    } else {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text("Help & Support", fontSize = 20.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                        Text("Raise tickets directly with CA/CS portal professionals.", fontSize = 12.sp, color = Color(0xFF64748B))
                    }
                    Button(
                        onClick = { isNewTicketOpen = true },
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6366F1))
                    ) {
                        Icon(Icons.Default.PlusOne, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Raise Ticket", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }

            if (viewModel.tickets.isEmpty()) {
                item {
                    Box(modifier = Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                        Text("No active tickets found.", color = Color(0xFF64748B))
                    }
                }
            } else {
                items(viewModel.tickets) { ticket ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(ticket.subject, fontWeight = FontWeight.Black, fontSize = 14.sp, color = Color(0xFF1E293B))
                                Box(
                                    modifier = Modifier
                                        .background(
                                            color = when (ticket.status) {
                                                "Closed" -> Color(0xFFEEF2F6)
                                                else -> Color(0xFFFEF3C7)
                                            },
                                            shape = RoundedCornerShape(6.dp)
                                        )
                                        .padding(horizontal = 6.dp, vertical = 2.dp)
                                ) {
                                    Text(ticket.status, fontSize = 9.sp, fontWeight = FontWeight.Black, color = if (ticket.status == "Closed") Color(0xFF64748B) else Color(0xFF92400E))
                                }
                            }
                            Text(
                                ticket.description,
                                fontSize = 12.sp,
                                color = Color(0xFF64748B),
                                modifier = Modifier.padding(top = 6.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}
