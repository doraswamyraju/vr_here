package com.sbr.vrherebms.ui.screens.admin

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.sbr.vrherebms.data.model.CreateTodoRequest
import com.sbr.vrherebms.ui.screens.hrms.HrmsAdminScreen
import com.sbr.vrherebms.ui.screens.admin.modules.*
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel
import com.sbr.vrherebms.viewmodel.AuthViewModel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminDashboardScreen(
    authViewModel: AuthViewModel,
    adminViewModel: AdminDashboardViewModel,
    userName: String,
    onLogout: () -> Unit
) {
    val context = LocalContext.current
    var activeTab by remember { mutableStateOf("Dashboard") }
    val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)
    val scope = rememberCoroutineScope()

    // Dialog state controllers
    var showNewOrderDialog by remember { mutableStateOf(false) }
    var showNewTodoDialog by remember { mutableStateOf(false) }
    var showNotificationsDialog by remember { mutableStateOf(false) }

    // Sync data on screen launch
    LaunchedEffect(Unit) {
        adminViewModel.syncDashboardData()

        // Silent periodic background polling every 15 seconds
        launch {
            while (true) {
                kotlinx.coroutines.delay(15000)
                adminViewModel.syncDashboardData(silent = true)
            }
        }
        
        // Listen to UI toast events
        adminViewModel.eventFlow.collectLatest { event ->
            when (event) {
                is AdminDashboardViewModel.UiEvent.ShowToast -> {
                    Toast.makeText(context, event.message, Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    // Colors matching React Web view exactly
    val primaryRed = Color(0xFFC82323)
    val textDark = Color(0xFF1E293B)
    val textMuted = Color(0xFF64748B)
    val boardBackground = Color(0xFFF1F5F9) // Sleek slate backdrop

    ModalNavigationDrawer(
        drawerState = drawerState,
        drawerContent = {
            ModalDrawerSheet(
                drawerContainerColor = Color(0xFF0F172A),
                drawerShape = RoundedCornerShape(topEnd = 24.dp, bottomEnd = 24.dp),
                modifier = Modifier.width(300.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(24.dp)
                ) {
                    // Header
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(32.dp)
                                .background(Color(0xFF3B82F6), RoundedCornerShape(8.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Text("VR", color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.Black)
                        }
                        Column {
                            Text(
                                text = "VR HERE",
                                color = Color.White,
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Black,
                                letterSpacing = 0.5.sp
                            )
                            Text(
                                text = "Admin Operations Center",
                                color = Color(0xFF94A3B8),
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(24.dp))
                    Divider(color = Color.White.copy(alpha = 0.1f))
                    Spacer(modifier = Modifier.height(16.dp))

                    // Menu items
                    val menuItems = listOf(
                        Triple("Dashboard", Icons.Default.Dashboard, "Studio Overview"),
                        Triple("Orders", Icons.Default.Layers, "Project Pipeline"),
                        Triple("Users", Icons.Default.Group, "User Directory"),
                        Triple("Todo", Icons.Default.CheckCircle, "Tasks Board"),
                        Triple("Finance", Icons.Default.AttachMoney, "Finance Ledger"),
                        Triple("Compliance", Icons.Default.Assignment, "Compliance Panel"),
                        Triple("Performance", Icons.Default.TrendingUp, "Performance Metrics"),
                        Triple("HRMS", Icons.Default.Badge, "HRMS Portal"),
                        Triple("Reports", Icons.Default.Assessment, "Business Reports"),
                        Triple("Notifications", Icons.Default.Notifications, "Admin Notifications"),
                        Triple("CRM", Icons.Default.Hub, "CRM Dashboard"),
                        Triple("KB", Icons.Default.Book, "KB Hub"),
                        Triple("Support", Icons.Default.Email, "Client Support"),
                        Triple("Services", Icons.Default.Settings, "Services Master"),
                        Triple("Referral", Icons.Default.Share, "Referral Ledger"),
                        Triple("Recurring", Icons.Default.Loop, "Recurring Hub"),
                        Triple("Settings", Icons.Default.SettingsApplications, "Global Settings")
                    )

                    Column(
                        modifier = Modifier
                            .weight(1f)
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        menuItems.forEach { (tabId, icon, label) ->
                            val isSelected = activeTab == tabId
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(
                                        if (isSelected) Color(0xFF1E293B) else Color.Transparent,
                                        RoundedCornerShape(12.dp)
                                    )
                                    .clickable {
                                        activeTab = tabId
                                        scope.launch { drawerState.close() }
                                    }
                                    .padding(horizontal = 16.dp, vertical = 12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                Icon(
                                    imageVector = icon,
                                    contentDescription = label,
                                    tint = if (isSelected) Color(0xFF3B82F6) else Color(0xFF94A3B8),
                                    modifier = Modifier.size(20.dp)
                                )
                                Text(
                                    text = label,
                                    color = if (isSelected) Color.White else Color(0xFFCBD5E1),
                                    fontSize = 13.sp,
                                    fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium
                                )
                            }
                        }
                    }

                    // Logout option
                    Divider(color = Color.White.copy(alpha = 0.1f))
                    Spacer(modifier = Modifier.height(16.dp))

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                scope.launch { drawerState.close() }
                                onLogout()
                            }
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.ExitToApp,
                            contentDescription = "Logout",
                            tint = Color(0xFFEF4444),
                            modifier = Modifier.size(20.dp)
                        )
                        Text(
                            text = "Sign Out",
                            color = Color(0xFFEF4444),
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }
    ) {
        Scaffold(
        topBar = {
            Surface(
                color = Color.White,
                tonalElevation = 2.dp,
                border = BorderStroke(1.dp, Color(0xFFEEF2F6))
            ) {
                Column {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .statusBarsPadding()
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        // 1. Hamburger menu in rounded box
                        Card(
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            modifier = Modifier.size(40.dp)
                        ) {
                            Box(
                                modifier = Modifier.fillMaxSize().clickable {
                                    scope.launch {
                                        drawerState.open()
                                    }
                                },
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(Icons.Default.Menu, contentDescription = "Menu", tint = textDark, modifier = Modifier.size(20.dp))
                            }
                        }

                        Spacer(modifier = Modifier.width(12.dp))

                        // 2. Title header text
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "VR Here Admin Panel",
                                fontSize = 11.sp,
                                color = textMuted,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = activeTab,
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Bold,
                                color = textDark
                            )
                        }

                        // 3. Notification box with Badge
                        val unreadCount = adminViewModel.notifications.count { !it.isRead }
                        Card(
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            modifier = Modifier.size(40.dp)
                        ) {
                            Box(
                                modifier = Modifier.fillMaxSize().clickable {
                                    showNotificationsDialog = true
                                },
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(Icons.Default.Notifications, contentDescription = "Notifications", tint = textDark, modifier = Modifier.size(20.dp))
                                // Red notification badge showing count
                                if (unreadCount > 0) {
                                    Box(
                                        modifier = Modifier
                                            .align(Alignment.TopEnd)
                                            .padding(2.dp)
                                            .size(16.dp)
                                            .background(primaryRed, CircleShape),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Text(
                                            text = unreadCount.toString(),
                                            color = Color.White,
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.Bold
                                        )
                                    }
                                }
                            }
                        }

                        Spacer(modifier = Modifier.width(8.dp))

                        // 4. Refresh button in rounded box
                        Card(
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            modifier = Modifier.size(40.dp)
                        ) {
                            Box(
                                modifier = Modifier.fillMaxSize().clickable {
                                    adminViewModel.syncDashboardData()
                                },
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = textDark, modifier = Modifier.size(20.dp))
                            }
                        }

                        Spacer(modifier = Modifier.width(8.dp))

                        // 5. Blue avatar box (User profile/Logout trigger)
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .background(Color(0xFF3B82F6), CircleShape)
                                .clickable {
                                    onLogout()
                                },
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = userName.take(1).uppercase(),
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 15.sp
                            )
                        }
                    }

                    // Dynamic Loading Bar
                    if (adminViewModel.isLoading) {
                        LinearProgressIndicator(
                            color = Color(0xFF6366F1),
                            modifier = Modifier.fillMaxWidth().height(3.dp)
                        )
                    }
                }
            }
        },
        bottomBar = {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFFF1F5F9))
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                contentAlignment = Alignment.Center
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(64.dp)
                        .background(Color(0xFA0F172A), RoundedCornerShape(28.dp))
                        .border(1.dp, Color(0xFFFFFFFF).copy(alpha = 0.15f), RoundedCornerShape(28.dp))
                        .padding(horizontal = 8.dp),
                    horizontalArrangement = Arrangement.SpaceAround,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    val navItems = listOf(
                        Triple("Dashboard", Icons.Default.Dashboard, "Studio"),
                        Triple("HRMS", Icons.Default.People, "HRMS")
                    )

                    navItems.forEach { (tabId, icon, label) ->
                        val isSelected = activeTab == tabId
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .clickable { activeTab = tabId }
                                .padding(vertical = 6.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.Center
                        ) {
                            Icon(
                                imageVector = icon,
                                contentDescription = label,
                                tint = if (isSelected) Color(0xFF3B82F6) else Color(0xFF94A3B8),
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(modifier = Modifier.height(3.dp))
                            Text(
                                text = label,
                                fontSize = 8.sp,
                                fontWeight = FontWeight.Bold,
                                color = if (isSelected) Color.White else Color(0xFF94A3B8).copy(alpha = 0.7f)
                            )
                        }
                    }
                }
            }
        },
        floatingActionButton = {
            if (activeTab == "Dashboard") {
                FloatingActionButton(
                    onClick = {
                        showNewOrderDialog = true
                    },
                    containerColor = Color(0xFF4F46E5),
                    contentColor = Color.White,
                    shape = CircleShape
                ) {
                    Icon(Icons.Default.Add, contentDescription = "Add New", modifier = Modifier.size(28.dp))
                }
            }
        }
    ) { paddingValues ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .background(boardBackground)
        ) {
            when (activeTab) {
                "Dashboard" -> {
                    AdminHomeTab(
                        adminViewModel = adminViewModel,
                        userName = userName,
                        onOpenNewOrder = { showNewOrderDialog = true },
                        onOpenNewTodo = { showNewTodoDialog = true },
                        onNavigate = { activeTab = it }
                    )
                }
                "Orders" -> {
                    AdminOrdersScreen(adminViewModel = adminViewModel)
                }
                "Users" -> {
                    AdminUsersScreen(adminViewModel = adminViewModel)
                }
                "Todo" -> {
                    AdminTodoScreen(adminViewModel = adminViewModel)
                }
                "Finance" -> {
                    AdminFinanceScreen(adminViewModel = adminViewModel)
                }
                "Compliance" -> {
                    AdminComplianceScreen(adminViewModel = adminViewModel)
                }
                "Performance" -> {
                    AdminPerformanceScreen(adminViewModel = adminViewModel)
                }
                "HRMS" -> {
                    AdminHrmsScreen()
                }
                "Reports" -> {
                    AdminReportsScreen(adminViewModel = adminViewModel)
                }
                "Notifications" -> {
                    AdminNotificationsScreen(adminViewModel = adminViewModel)
                }
                "CRM" -> {
                    AdminCrmScreen(adminViewModel = adminViewModel)
                }
                "KB" -> {
                    AdminKbScreen()
                }
                "Support" -> {
                    AdminSupportScreen(adminViewModel = adminViewModel)
                }
                "Services" -> {
                    AdminServicesScreen()
                }
                "Referral" -> {
                    AdminReferralScreen(adminViewModel = adminViewModel)
                }
                "Recurring" -> {
                    AdminRecurringScreen(adminViewModel = adminViewModel)
                }
                "Settings" -> {
                    AdminSettingsScreen()
                }
            }

            // Lockscreen-style Heads-up In-app Notification Banner for Admin
            AnimatedVisibility(
                visible = adminViewModel.activeBannerNotification != null,
                enter = slideInVertically(
                    initialOffsetY = { -it },
                    animationSpec = spring(
                        dampingRatio = Spring.DampingRatioLowBouncy,
                        stiffness = Spring.StiffnessMediumLow
                    )
                ) + fadeIn(),
                exit = slideOutVertically(
                    targetOffsetY = { -it },
                    animationSpec = spring(
                        dampingRatio = Spring.DampingRatioNoBouncy,
                        stiffness = Spring.StiffnessMedium
                    )
                ) + fadeOut(),
                modifier = Modifier
                    .align(Alignment.TopCenter)
                    .padding(top = 16.dp, start = 16.dp, end = 16.dp)
                    .fillMaxWidth()
                    .wrapContentHeight()
            ) {
                adminViewModel.activeBannerNotification?.let { notif ->
                    LaunchedEffect(notif.id) {
                        kotlinx.coroutines.delay(5000)
                        adminViewModel.dismissBanner()
                    }

                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .shadow(24.dp, RoundedCornerShape(20.dp))
                            .clickable {
                                adminViewModel.dismissBanner()
                                showNotificationsDialog = true
                            },
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(
                            containerColor = Color(0xFF0F172A).copy(alpha = 0.95f)
                        ),
                        border = BorderStroke(
                            1.dp,
                            Brush.horizontalGradient(
                                listOf(Color(0xFF6366F1).copy(alpha = 0.5f), Color(0xFF8B5CF6).copy(alpha = 0.3f))
                            )
                        )
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(20.dp)
                                            .background(Color(0xFF6366F1), RoundedCornerShape(6.dp)),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Text("VR", color = Color.White, fontSize = 8.sp, fontWeight = FontWeight.Black)
                                    }
                                    Text(
                                        text = "VR HERE ADMIN",
                                        color = Color(0xFF818CF8),
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Black,
                                        letterSpacing = 0.5.sp
                                    )
                                    Text(
                                        text = "• Just now",
                                        color = Color(0xFF94A3B8),
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                                IconButton(
                                    onClick = { adminViewModel.dismissBanner() },
                                    modifier = Modifier.size(20.dp)
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Clear,
                                        contentDescription = "Close",
                                        tint = Color(0xFF94A3B8),
                                        modifier = Modifier.size(12.dp)
                                    )
                                }
                            }
                            Spacer(modifier = Modifier.height(10.dp))
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(36.dp)
                                        .background(Color(0xFF1E293B), RoundedCornerShape(10.dp)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Notifications,
                                        contentDescription = null,
                                        tint = Color(0xFF6366F1),
                                        modifier = Modifier.size(16.dp)
                                    )
                                }
                                Column(
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text(
                                        text = notif.title,
                                        color = Color.White,
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.Black
                                    )
                                    Spacer(modifier = Modifier.height(2.dp))
                                    Text(
                                        text = notif.message,
                                        color = Color(0xFFCBD5E1),
                                        fontSize = 11.sp,
                                        lineHeight = 14.sp
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

    // A. PREMIUM MANUAL SERVICE ORDER DIALOG FORM
    if (showNewOrderDialog) {
        Dialog(onDismissRequest = { showNewOrderDialog = false }) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(8.dp),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFF1F5F9)),
                elevation = CardDefaults.cardElevation(defaultElevation = 8.dp)
            ) {
                Column(
                    modifier = Modifier
                        .padding(24.dp)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Text(
                        text = "Register Manual Service",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Black,
                        color = textDark
                    )

                    var clientName by remember { mutableStateOf("") }
                    var email by remember { mutableStateOf("") }
                    var phone by remember { mutableStateOf("") }
                    var serviceName by remember { mutableStateOf("") }
                    var packageName by remember { mutableStateOf("Standard Plan") }
                    var price by remember { mutableStateOf("") }
                    
                    var expandedService by remember { mutableStateOf(false) }
                    val serviceOptions = listOf(
                        "Private Limited Company Registration",
                        "GST Registration",
                        "GST Return Filing",
                        "Income Tax Return",
                        "MSME / Udyam Registration",
                        "Trademark Registration",
                        "Company Annual Compliances"
                    )

                    var expandedEmployee by remember { mutableStateOf(false) }
                    var selectedEmployeeId by remember { mutableStateOf<String?>(null) }
                    var selectedEmployeeName by remember { mutableStateOf("Select Specialist (Optional)") }

                    OutlinedTextField(
                        value = clientName,
                        onValueChange = { clientName = it },
                        label = { Text("Client Full Name") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp)
                    )

                    OutlinedTextField(
                        value = email,
                        onValueChange = { email = it },
                        label = { Text("Client Email") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email)
                    )

                    OutlinedTextField(
                        value = phone,
                        onValueChange = { phone = it },
                        label = { Text("Client Phone") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone)
                    )

                    // Service Dropdown
                    Box(modifier = Modifier.fillMaxWidth()) {
                        OutlinedTextField(
                            value = serviceName,
                            onValueChange = { serviceName = it },
                            label = { Text("Service Name") },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            trailingIcon = {
                                IconButton(onClick = { expandedService = true }) {
                                    Icon(Icons.Default.ArrowDropDown, contentDescription = "Dropdown")
                                }
                            }
                        )
                        DropdownMenu(
                            expanded = expandedService,
                            onDismissRequest = { expandedService = false },
                            modifier = Modifier.fillMaxWidth(0.9f)
                        ) {
                            serviceOptions.forEach { service ->
                                DropdownMenuItem(
                                    text = { Text(service) },
                                    onClick = {
                                        serviceName = service
                                        expandedService = false
                                    }
                                )
                            }
                        }
                    }

                    OutlinedTextField(
                        value = packageName,
                        onValueChange = { packageName = it },
                        label = { Text("Package Plan") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp)
                    )

                    OutlinedTextField(
                        value = price,
                        onValueChange = { price = it },
                        label = { Text("Valuation Price (INR)") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                    )

                    // Employee Dropdown Assignment
                    Box(modifier = Modifier.fillMaxWidth()) {
                        OutlinedTextField(
                            value = selectedEmployeeName,
                            onValueChange = {},
                            readOnly = true,
                            label = { Text("Assign Specialist") },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            trailingIcon = {
                                IconButton(onClick = { expandedEmployee = true }) {
                                    Icon(Icons.Default.Person, contentDescription = "Dropdown")
                                }
                            }
                        )
                        DropdownMenu(
                            expanded = expandedEmployee,
                            onDismissRequest = { expandedEmployee = false },
                            modifier = Modifier.fillMaxWidth(0.9f)
                        ) {
                            DropdownMenuItem(
                                text = { Text("Unassigned") },
                                onClick = {
                                    selectedEmployeeId = null
                                    selectedEmployeeName = "Unassigned"
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

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        TextButton(onClick = { showNewOrderDialog = false }) {
                            Text("Cancel", color = textMuted)
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Button(
                            onClick = {
                                if (clientName.isBlank() || serviceName.isBlank() || price.isBlank()) {
                                    Toast.makeText(context, "Please fill Client Name, Service Name, and Price", Toast.LENGTH_SHORT).show()
                                    return@Button
                                }
                                val priceValue = price.toDoubleOrNull() ?: 0.0
                                val payload = mutableMapOf<String, Any>(
                                    "clientName" to clientName,
                                    "email" to email,
                                    "phone" to phone,
                                    "serviceName" to serviceName,
                                    "packageName" to packageName,
                                    "price" to priceValue
                                )
                                selectedEmployeeId?.let { payload["assignedEmployee"] = it }

                                adminViewModel.createOrder(payload) { success ->
                                    if (success) showNewOrderDialog = false
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10B981)),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Text("Create Order", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }
    }

    // B. PREMIUM MANUALLY CREATED TO-DO DIALOG FORM
    if (showNewTodoDialog) {
        Dialog(onDismissRequest = { showNewTodoDialog = false }) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(8.dp),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFF1F5F9)),
                elevation = CardDefaults.cardElevation(defaultElevation = 8.dp)
            ) {
                Column(
                    modifier = Modifier
                        .padding(24.dp)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Text(
                        text = "Create Admin task",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Black,
                        color = textDark
                    )

                    var title by remember { mutableStateOf("") }
                    var description by remember { mutableStateOf("") }
                    var priority by remember { mutableStateOf("Medium") }
                    
                    var expandedPriority by remember { mutableStateOf(false) }
                    val priorityOptions = listOf("Low", "Medium", "High")

                    var expandedEmployee by remember { mutableStateOf(false) }
                    var selectedEmployeeId by remember { mutableStateOf<String?>(null) }
                    var selectedEmployeeName by remember { mutableStateOf("Assign Employee (Optional)") }

                    OutlinedTextField(
                        value = title,
                        onValueChange = { title = it },
                        label = { Text("Task Title") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp)
                    )

                    OutlinedTextField(
                        value = description,
                        onValueChange = { description = it },
                        label = { Text("Detailed Instructions") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        minLines = 3
                    )

                    // Priority dropdown
                    Box(modifier = Modifier.fillMaxWidth()) {
                        OutlinedTextField(
                            value = priority,
                            onValueChange = {},
                            readOnly = true,
                            label = { Text("Priority Level") },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            trailingIcon = {
                                IconButton(onClick = { expandedPriority = true }) {
                                    Icon(Icons.Default.ArrowDropDown, contentDescription = "Dropdown")
                                }
                            }
                        )
                        DropdownMenu(
                            expanded = expandedPriority,
                            onDismissRequest = { expandedPriority = false }
                        ) {
                            priorityOptions.forEach { level ->
                                DropdownMenuItem(
                                    text = { Text(level) },
                                    onClick = {
                                        priority = level
                                        expandedPriority = false
                                    }
                                )
                            }
                        }
                    }

                    // Employee dropdown assignment
                    Box(modifier = Modifier.fillMaxWidth()) {
                        OutlinedTextField(
                            value = selectedEmployeeName,
                            onValueChange = {},
                            readOnly = true,
                            label = { Text("Assign Staff") },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            trailingIcon = {
                                IconButton(onClick = { expandedEmployee = true }) {
                                    Icon(Icons.Default.Person, contentDescription = "Dropdown")
                                }
                            }
                        )
                        DropdownMenu(
                            expanded = expandedEmployee,
                            onDismissRequest = { expandedEmployee = false },
                            modifier = Modifier.fillMaxWidth(0.9f)
                        ) {
                            DropdownMenuItem(
                                text = { Text("Unassigned") },
                                onClick = {
                                    selectedEmployeeId = null
                                    selectedEmployeeName = "Unassigned"
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

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        TextButton(onClick = { showNewTodoDialog = false }) {
                            Text("Cancel", color = textMuted)
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Button(
                            onClick = {
                                if (title.isBlank()) {
                                    Toast.makeText(context, "Task Title is required", Toast.LENGTH_SHORT).show()
                                    return@Button
                                }
                                val request = CreateTodoRequest(
                                    title = title,
                                    description = if (description.isBlank()) null else description,
                                    priority = priority,
                                    assignedTo = selectedEmployeeId,
                                    orderId = null,
                                    dueDate = null
                                )

                                adminViewModel.createTodo(request) { success ->
                                    if (success) showNewTodoDialog = false
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF59E0B)),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Text("Add Task", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }
    }

    // C. PREMIUM NOTIFICATIONS LIST DIALOG
    if (showNotificationsDialog) {
        Dialog(onDismissRequest = { showNotificationsDialog = false }) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(450.dp)
                    .padding(8.dp),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFF1F5F9)),
                elevation = CardDefaults.cardElevation(defaultElevation = 8.dp)
            ) {
                Column(
                    modifier = Modifier.padding(24.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Admin Notifications",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Black,
                            color = textDark
                        )
                        IconButton(onClick = { showNotificationsDialog = false }) {
                            Icon(Icons.Default.Clear, contentDescription = "Close", tint = textMuted)
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    val notifList = adminViewModel.notifications
                    if (notifList.isEmpty()) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .weight(1f),
                            contentAlignment = Alignment.Center
                        ) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Icon(
                                    imageVector = Icons.Default.Notifications,
                                    contentDescription = null,
                                    tint = textMuted.copy(alpha = 0.3f),
                                    modifier = Modifier.size(48.dp)
                                )
                                Spacer(modifier = Modifier.height(8.dp))
                                Text("All caught up!", color = textMuted, fontSize = 13.sp)
                            }
                        }
                    } else {
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .verticalScroll(rememberScrollState()),
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            notifList.forEach { notif ->
                                val cardBg = if (notif.isRead) Color(0xFFF8FAFC) else Color(0xFFFFECEC)
                                Card(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            adminViewModel.markNotificationAsRead(notif.id)
                                        },
                                    colors = CardDefaults.cardColors(containerColor = cardBg),
                                    shape = RoundedCornerShape(12.dp),
                                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                                ) {
                                    Row(
                                        modifier = Modifier.padding(12.dp),
                                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Box(
                                            modifier = Modifier
                                                .size(36.dp)
                                                .background(
                                                    if (notif.isRead) Color(0xFFE2E8F0) else Color(0xFFFFCDCD),
                                                    CircleShape
                                                ),
                                            contentAlignment = Alignment.Center
                                        ) {
                                            Icon(
                                                imageVector = Icons.Default.Notifications,
                                                contentDescription = null,
                                                tint = if (notif.isRead) textMuted else primaryRed,
                                                modifier = Modifier.size(18.dp)
                                            )
                                        }
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(
                                                text = notif.title,
                                                fontWeight = FontWeight.Bold,
                                                color = textDark,
                                                fontSize = 13.sp
                                            )
                                            Spacer(modifier = Modifier.height(2.dp))
                                            Text(
                                                text = notif.message,
                                                color = textMuted,
                                                fontSize = 12.sp,
                                                lineHeight = 16.sp
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    Button(
                        onClick = { showNotificationsDialog = false },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = primaryRed),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text("Close", fontWeight = FontWeight.Bold, color = Color.White)
                    }
                }
            }
        }
    }
}
