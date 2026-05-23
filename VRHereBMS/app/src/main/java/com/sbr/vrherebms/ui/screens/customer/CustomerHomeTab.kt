package com.sbr.vrherebms.ui.screens.customer

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel

@OptIn(ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)
@Composable
fun CustomerHomeTab(
    viewModel: CustomerDashboardViewModel,
    userName: String,
    searchQuery: String,
    onSearchQueryChange: (String) -> Unit,
    onSelectTab: (String) -> Unit,
    onOpenProject: (String) -> Unit,
    onOpenLiveService: (String, String) -> Unit
) {
    val context = LocalContext.current
    var showSuggestions by remember { mutableStateOf(false) }

    val searchSuggestions = listOf(
        "Private Limited Company Registration",
        "Limited Liability Partnership (LLP)",
        "GST Registration",
        "GST Return Filing",
        "Income Tax Return",
        "MSME / Udyam Registration",
        "Trademark Registration",
        "FSSAI Food License",
        "ISO Certification",
        "Import Export Code (IEC)",
        "Company Annual Compliances",
        "Startup India DPIIT Registration"
    )

    val filteredSuggestions = remember(searchQuery) {
        searchSuggestions.filter { it.contains(searchQuery, ignoreCase = true) }.take(5)
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(top = 16.dp, bottom = 120.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp)
    ) {
        // Hello Heading Section
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "Hello, ${userName.split(" ").firstOrNull() ?: "Guest"}!",
                        fontSize = 24.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFF1E293B),
                        letterSpacing = (-0.5).sp
                    )
                    Text(
                        text = "Here's what's happening today.",
                        fontSize = 13.sp,
                        color = Color(0xFF64748B)
                    )
                }
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    // Notification Bell Button
                    val unreadNotifications = viewModel.notifications.filter { !it.isRead }
                    val unreadCount = unreadNotifications.size
                    var showNotificationDialog by remember { mutableStateOf(false) }

                    Box(
                        modifier = Modifier
                            .size(42.dp)
                            .background(Color(0xFFEEF2F6), RoundedCornerShape(12.dp))
                            .scaleOnPress()
                            .clickable { showNotificationDialog = true },
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = if (unreadCount > 0) Icons.Default.NotificationsActive else Icons.Default.Notifications,
                            contentDescription = "Notifications",
                            tint = Color(0xFF6366F1),
                            modifier = Modifier.size(20.dp)
                        )
                        if (unreadCount > 0) {
                            Box(
                                modifier = Modifier
                                    .size(8.dp)
                                    .align(Alignment.TopEnd)
                                    .padding(top = 8.dp, end = 8.dp)
                                    .background(Color(0xFFEF4444), CircleShape)
                            )
                        }
                    }

                    // Refresh Button
                    Box(
                        modifier = Modifier
                            .size(42.dp)
                            .background(Color(0xFFEEF2F6), RoundedCornerShape(12.dp))
                            .scaleOnPress()
                            .clickable { viewModel.refreshAllData() },
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Refresh,
                            contentDescription = "Refresh",
                            tint = Color(0xFF6366F1),
                            modifier = Modifier.size(20.dp)
                        )
                    }

                    // Notification dialog
                    if (showNotificationDialog) {
                        AlertDialog(
                            onDismissRequest = { showNotificationDialog = false },
                            confirmButton = {
                                TextButton(onClick = { showNotificationDialog = false }) {
                                    Text("Close", color = Color(0xFF6366F1), fontWeight = FontWeight.Bold)
                                }
                            },
                            title = {
                                Text(
                                    "Notifications",
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF1E293B)
                                )
                            },
                            text = {
                                Box(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .heightIn(max = 400.dp)
                                ) {
                                    if (viewModel.notifications.isEmpty()) {
                                        Box(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .padding(24.dp),
                                            contentAlignment = Alignment.Center
                                        ) {
                                            Text(
                                                "No notifications available.",
                                                color = Color(0xFF64748B),
                                                fontSize = 13.sp
                                            )
                                        }
                                    } else {
                                        LazyColumn(
                                            verticalArrangement = Arrangement.spacedBy(8.dp),
                                            modifier = Modifier.fillMaxWidth()
                                        ) {
                                            items(viewModel.notifications) { notification ->
                                                Card(
                                                    modifier = Modifier
                                                        .fillMaxWidth()
                                                        .clickable {
                                                            if (!notification.isRead) {
                                                                viewModel.markNotificationAsRead(notification.id)
                                                            }
                                                        },
                                                    shape = RoundedCornerShape(16.dp),
                                                    colors = CardDefaults.cardColors(
                                                        containerColor = if (notification.isRead) Color(0xFFF8FAFC) else Color(0xFFF1F5F9)
                                                    ),
                                                    border = BorderStroke(
                                                        1.dp, 
                                                        if (notification.isRead) Color(0xFFE2E8F0) else Color(0xFF6366F1).copy(alpha = 0.2f)
                                                    )
                                                ) {
                                                    Column(
                                                        modifier = Modifier.padding(12.dp)
                                                    ) {
                                                        // Brand header inside card
                                                        Row(
                                                            modifier = Modifier.fillMaxWidth(),
                                                            horizontalArrangement = Arrangement.SpaceBetween,
                                                            verticalAlignment = Alignment.CenterVertically
                                                        ) {
                                                            Row(
                                                                verticalAlignment = Alignment.CenterVertically,
                                                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                                                            ) {
                                                                Box(
                                                                    modifier = Modifier
                                                                        .size(16.dp)
                                                                        .background(Color(0xFF6366F1), RoundedCornerShape(4.dp)),
                                                                    contentAlignment = Alignment.Center
                                                                ) {
                                                                    Text("VR", color = Color.White, fontSize = 7.sp, fontWeight = FontWeight.Black)
                                                                }
                                                                Text(
                                                                    text = "VR HERE", 
                                                                    color = Color(0xFF475569), 
                                                                    fontSize = 9.sp, 
                                                                    fontWeight = FontWeight.Black, 
                                                                    letterSpacing = 0.3.sp
                                                                )
                                                                if (!notification.isRead) {
                                                                    Box(
                                                                        modifier = Modifier
                                                                            .size(5.dp)
                                                                            .background(Color(0xFF6366F1), CircleShape)
                                                                    )
                                                                }
                                                            }
                                                            // Optional type badge or dot
                                                            Box(
                                                                modifier = Modifier
                                                                    .background(Color(0xFFEEF2F6), RoundedCornerShape(4.dp))
                                                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                                                            ) {
                                                                Text(
                                                                    text = notification.type.uppercase(),
                                                                    fontSize = 7.sp,
                                                                    fontWeight = FontWeight.Black,
                                                                    color = Color(0xFF6366F1)
                                                                )
                                                            }
                                                        }
                                                        Spacer(modifier = Modifier.height(8.dp))
                                                        // Text block
                                                        Text(
                                                            text = notification.title,
                                                            fontSize = 12.sp,
                                                            fontWeight = FontWeight.Black,
                                                            color = Color(0xFF1E293B)
                                                        )
                                                        Spacer(modifier = Modifier.height(2.dp))
                                                        Text(
                                                            text = notification.message,
                                                            fontSize = 11.sp,
                                                            color = Color(0xFF64748B),
                                                            lineHeight = 14.sp
                                                        )
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            shape = RoundedCornerShape(24.dp),
                            containerColor = Color.White
                        )
                    }
                }
            }
        }

        // Floating Search Bar with Autocomplete suggestions
        item {
            Column(modifier = Modifier.fillMaxWidth()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .shadow(4.dp, RoundedCornerShape(16.dp))
                        .background(Color.White, RoundedCornerShape(16.dp))
                        .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(16.dp))
                        .padding(horizontal = 14.dp, vertical = 6.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(
                            imageVector = Icons.Default.Search,
                            contentDescription = "Search",
                            tint = Color(0xFF94A3B8),
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        TextField(
                            value = searchQuery,
                            onValueChange = {
                                onSearchQueryChange(it)
                                showSuggestions = it.isNotEmpty()
                            },
                            placeholder = {
                                Text(
                                    "Search services (e.g. GST, Company...)",
                                    fontSize = 13.sp,
                                    color = Color(0xFF94A3B8)
                                )
                            },
                            colors = TextFieldDefaults.colors(
                                focusedContainerColor = Color.Transparent,
                                unfocusedContainerColor = Color.Transparent,
                                disabledContainerColor = Color.Transparent,
                                errorContainerColor = Color.Transparent,
                                focusedIndicatorColor = Color.Transparent,
                                unfocusedIndicatorColor = Color.Transparent,
                                disabledIndicatorColor = Color.Transparent
                            ),
                            singleLine = true,
                            modifier = Modifier.weight(1f)
                        )
                        if (searchQuery.isNotEmpty()) {
                            IconButton(
                                onClick = {
                                    onSearchQueryChange("")
                                    showSuggestions = false
                                },
                                modifier = Modifier.size(24.dp)
                            ) {
                                Icon(Icons.Default.Clear, contentDescription = "Clear", tint = Color(0xFF94A3B8))
                            }
                        }
                    }
                }

                // Suggestion Dropdown List
                if (showSuggestions && searchQuery.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .shadow(8.dp, RoundedCornerShape(16.dp)),
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(vertical = 8.dp)) {
                            if (filteredSuggestions.isNotEmpty()) {
                                filteredSuggestions.forEach { suggestion ->
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clickable {
                                                val liveSuggestionsMap = mapOf(
                                                    "Private Limited Company Registration" to Pair("Private Limited Company Registration", "https://vrhere.in/pvt-ltd-registration"),
                                                    "Limited Liability Partnership (LLP)" to Pair("Partnership Firm Registration", "https://vrhere.in/partnership-firm"),
                                                    "GST Registration" to Pair("GST Registration", "https://vrhere.in/gst-registration"),
                                                    "GST Return Filing" to Pair("GST Return Filing", "https://vrhere.in/accounting-services"),
                                                    "Income Tax Return" to Pair("Income Tax Return Filing", "https://vrhere.in/income-tax-return"),
                                                    "Company Annual Compliances" to Pair("Companies Compliance Scheme 2026 (CCFS)", "https://vrhere.in/compliance-scheme-2026")
                                                )
                                                val target = liveSuggestionsMap[suggestion]
                                                if (target != null) {
                                                    onOpenLiveService(target.first, target.second)
                                                } else {
                                                    onSearchQueryChange(suggestion)
                                                    onSelectTab("Services")
                                                }
                                                showSuggestions = false
                                            }
                                            .padding(horizontal = 16.dp, vertical = 12.dp),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            text = suggestion,
                                            fontSize = 13.sp,
                                            fontWeight = FontWeight.Medium,
                                            color = Color(0xFF334155)
                                        )
                                        Icon(
                                            imageVector = Icons.Default.ArrowForward,
                                            contentDescription = "Select",
                                            tint = Color(0xFFCBD5E1),
                                            modifier = Modifier.size(14.dp)
                                        )
                                    }
                                }
                            } else {
                                Box(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(16.dp),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                        Text(
                                            "Service not listed?",
                                            fontSize = 11.sp,
                                            color = Color(0xFF94A3B8),
                                            fontWeight = FontWeight.Bold
                                        )
                                        Spacer(modifier = Modifier.height(6.dp))
                                        Button(
                                            onClick = { onSelectTab("Support") },
                                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6366F1)),
                                            shape = RoundedCornerShape(8.dp)
                                        ) {
                                            Text("Request Custom Service", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Indigo Active Portfolio Gradient Card
        item {
            val activeCount = viewModel.orders.filter { it.status != "Completed" }.size
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(28.dp),
                border = BorderStroke(1.dp, Color(0xFFFFFFFF).copy(alpha = 0.2f))
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            brush = Brush.linearGradient(
                                listOf(Color(0xFF4F46E5), Color(0xFF6D28D9))
                            )
                        )
                        .padding(24.dp)
                ) {
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.BusinessCenter,
                                contentDescription = null,
                                tint = Color.White.copy(alpha = 0.8f),
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "ACTIVE PORTFOLIO",
                                color = Color.White.copy(alpha = 0.8f),
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Black,
                                letterSpacing = 1.sp
                            )
                        }
                        Spacer(modifier = Modifier.height(16.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.Bottom
                        ) {
                            Column {
                                Text(
                                    text = activeCount.toString(),
                                    color = Color.White,
                                    fontSize = 44.sp,
                                    fontWeight = FontWeight.Black,
                                    lineHeight = 44.sp
                                )
                                Text(
                                    text = "Projects currently in progress",
                                    color = Color(0xFFE0E7FF),
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                            Button(
                                onClick = { onSelectTab("Orders") },
                                colors = ButtonDefaults.buttonColors(containerColor = Color.White),
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier.scaleOnPress(),
                                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 10.dp)
                            ) {
                                Text(
                                    text = "Track Status",
                                    color = Color(0xFF4F46E5),
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Black
                                )
                            }
                        }
                    }
                }
            }
        }

        // Quick Access Services 4x2 Grid (Exact match of HSL icons and keys)
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(32.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFF1F5F9))
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Quick Access Services",
                            fontWeight = FontWeight.Black,
                            fontSize = 15.sp,
                            color = Color(0xFF1E293B)
                        )
                        Text(
                            text = "View Catalog",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF6366F1),
                            modifier = Modifier
                                .clickable { onSelectTab("Services") }
                                .scaleOnPress()
                        )
                    }
                    Spacer(modifier = Modifier.height(20.dp))

                    data class QuickAccessService(
                        val name: String,
                        val icon: ImageVector,
                        val bg: Color,
                        val tint: Color
                    )

                    val topServices = listOf(
                        QuickAccessService("Pvt Ltd", Icons.Default.Business, Color(0xFFEFF6FF), Color(0xFF2563EB)),
                        QuickAccessService("GST", Icons.Default.FactCheck, Color(0xFFF0FDF4), Color(0xFF16A34A)),
                        QuickAccessService("IT Return", Icons.Default.Computer, Color(0xFFEEF2F6), Color(0xFF4F46E5)),
                        QuickAccessService("Partnership", Icons.Default.People, Color(0xFFFEF3C7), Color(0xFFD97706)),
                        QuickAccessService("Trademark", Icons.Default.Security, Color(0xFFF3E8FF), Color(0xFF9333EA)),
                        QuickAccessService("Audit", Icons.Default.AssignmentTurnedIn, Color(0xFFFFF1F2), Color(0xFFE11D48)),
                        QuickAccessService("Funding", Icons.Default.CurrencyRupee, Color(0xFFECFDF5), Color(0xFF059669)),
                        QuickAccessService("Compliance", Icons.Default.Settings, Color(0xFFF8FAFC), Color(0xFF475569))
                    )

                    // 4-column layout
                    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                        for (row in 0 until 2) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                for (col in 0 until 4) {
                                    val idx = row * 4 + col
                                    if (idx < topServices.size) {
                                        val service = topServices[idx]
                                        Column(
                                            horizontalAlignment = Alignment.CenterHorizontally,
                                            modifier = Modifier
                                                .weight(1f)
                                                .scaleOnPress()
                                                .clickable { onSelectTab("Services") }
                                        ) {
                                            Box(
                                                modifier = Modifier
                                                    .size(54.dp)
                                                    .background(service.bg, RoundedCornerShape(16.dp)),
                                                contentAlignment = Alignment.Center
                                            ) {
                                                Icon(
                                                    imageVector = service.icon,
                                                    contentDescription = service.name,
                                                    tint = service.tint,
                                                    modifier = Modifier.size(22.dp)
                                                )
                                            }
                                            Spacer(modifier = Modifier.height(6.dp))
                                            Text(
                                                text = service.name,
                                                fontSize = 10.sp,
                                                fontWeight = FontWeight.Black,
                                                color = Color(0xFF475569),
                                                textAlign = TextAlign.Center,
                                                maxLines = 1,
                                                overflow = TextOverflow.Ellipsis
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

        // Live Operational Pipeline Section
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Operational Pipeline",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF1E293B),
                    letterSpacing = (-0.5).sp
                )
                Box(
                    modifier = Modifier
                        .background(Color(0xFFEEF2F6), RoundedCornerShape(8.dp))
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Text(
                        "LIVE UPDATES",
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFF6366F1)
                    )
                }
            }
        }

        val activeOrders = viewModel.orders.filter { it.status != "Completed" }
        if (activeOrders.isEmpty()) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(32.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Box(
                            modifier = Modifier
                                .size(56.dp)
                                .background(Color(0xFFEEF2F6), CircleShape),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.Add, contentDescription = null, tint = Color(0xFF64748B), modifier = Modifier.size(24.dp))
                        }
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            "Your pipeline is empty",
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF334155)
                        )
                        Text(
                            "Start a new project to see it tracked here live.",
                            fontSize = 11.sp,
                            color = Color(0xFF64748B),
                            modifier = Modifier.padding(top = 4.dp)
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Button(
                            onClick = { onSelectTab("Services") },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6366F1)),
                            modifier = Modifier.scaleOnPress(),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Text("Start Now", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        } else {
            items(activeOrders.take(3)) { order ->
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .scaleOnPress()
                        .clickable { onOpenProject(order.id) },
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFF1F5F9))
                ) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.Top
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = order.serviceName,
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF1E293B)
                                )
                                Text(
                                    text = order.packageName,
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFF94A3B8),
                                    modifier = Modifier.padding(top = 2.dp)
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

        // Stats sidebar equivalents in grid
        item {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                val pendingActions = viewModel.orders.filter { it.status == "Pending Documents" || it.status == "Waiting for Clarification" }.size
                val totalValue = viewModel.orders.sumOf { it.price }

                Card(
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFF1F5F9))
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .background(Color(0xFFFEF3C7), RoundedCornerShape(12.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.Warning, contentDescription = null, tint = Color(0xFFD97706), modifier = Modifier.size(20.dp))
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text("Attention", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                            Text("$pendingActions Tasks", fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                        }
                    }
                }

                Card(
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFF1F5F9))
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .background(Color(0xFFD1FAE5), RoundedCornerShape(12.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.CurrencyRupee, contentDescription = null, tint = Color(0xFF059669), modifier = Modifier.size(20.dp))
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text("Investment", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                            Text("₹${(totalValue / 1000).toInt()}k", fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                        }
                    }
                }
            }
        }

        // Accounting CTA Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(28.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF064E3B))
            ) {
                Column(modifier = Modifier.padding(24.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .background(Color(0xFF10B981).copy(alpha = 0.2f), RoundedCornerShape(12.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.AssignmentTurnedIn, contentDescription = null, tint = Color(0xFF34D399), modifier = Modifier.size(20.dp))
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Text("Accounting Services", color = Color.White, fontWeight = FontWeight.Black, fontSize = 16.sp)
                    }
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        "Customize your own GST, TDS, and Payroll packages with our multi-select builder.",
                        color = Color(0xFFA7F3D0),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Button(
                        onClick = { onSelectTab("Services") },
                        colors = ButtonDefaults.buttonColors(containerColor = Color.White),
                        modifier = Modifier
                            .fillMaxWidth()
                            .scaleOnPress(),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text("Build Package", color = Color(0xFF064E3B), fontWeight = FontWeight.Black, fontSize = 11.sp)
                    }
                }
            }
        }

        // Insights / News Alert Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(28.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFF1F5F9))
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("Insights Feed", fontWeight = FontWeight.Black, fontSize = 14.sp, color = Color(0xFF1E293B))
                        Box(
                            modifier = Modifier
                                .background(Color(0xFFEEF2F6), RoundedCornerShape(6.dp))
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                        ) {
                            Text("ALERT", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF6366F1))
                        }
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        "GST Compliance: New Rules for IT Credit in 2026",
                        fontWeight = FontWeight.Black,
                        fontSize = 13.sp,
                        color = Color(0xFF1E293B)
                    )
                    Text(
                        "Stay ahead with latest amendments in GST laws affecting MSMEs and industrial inputs.",
                        fontSize = 11.sp,
                        color = Color(0xFF64748B),
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
            }
        }
    }
}
