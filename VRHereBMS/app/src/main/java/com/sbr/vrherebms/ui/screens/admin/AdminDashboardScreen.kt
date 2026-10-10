package com.sbr.vrherebms.ui.screens.admin

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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

    // Auto-switch to Orders tab when a project/order is selected
    LaunchedEffect(adminViewModel.selectedOrderId) {
        if (adminViewModel.selectedOrderId != null) {
            activeTab = "Orders"
        }
    }

    // Colors matching React Web view exactly
    val primaryRed = Color(0xFFC82323)
    val textDark = Color(0xFF1E293B)
    val textMuted = Color(0xFF64748B)
    val boardBackground = Color(0xFFF1F5F9) // Sleek slate backdrop

    val pendingOrdersCount = adminViewModel.orders.count {
        val s = it.status.lowercase()
        s.contains("pending") || s.contains("processing")
    }

    val dockItems = remember {
        listOf(
            com.sbr.vrherebms.ui.components.DockItem("Dashboard", "Overview", Icons.Default.PieChart),
            com.sbr.vrherebms.ui.components.DockItem("Orders", "Orders", Icons.Default.Layers),
            com.sbr.vrherebms.ui.components.DockItem("Leads", "Leads", Icons.Default.LocalFireDepartment),
            com.sbr.vrherebms.ui.components.DockItem("HRMS", "HRMS", Icons.Default.Badge),
            com.sbr.vrherebms.ui.components.DockItem("Users", "Users", Icons.Default.Group)
        )
    }

    val sidebarItems = remember {
        listOf(
            com.sbr.vrherebms.ui.components.BMSSidebarItem("Dashboard", "Dashboard", Icons.Default.PieChart),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("Leads", "Leads CRM", Icons.Default.LocalFireDepartment),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("Orders", "Orders", Icons.Default.Layers),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("Blogs", "Blogs & Insights", Icons.Default.MenuBook),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("Offers", "Offers & Schemes", Icons.Default.AutoAwesome),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("Users", "Users", Icons.Default.Group),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("Freelancers", "Freelancer Hub", Icons.Default.PeopleOutline),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("ToDo", "To Do", Icons.Default.CheckCircle),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("Compliance", "Compliance", Icons.Default.AssignmentTurnedIn),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("ITChecklist", "IT Checklist", Icons.Default.Description),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("Performance", "Performance", Icons.Default.TrendingUp),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("HRMS", "HRMS Portal", Icons.Default.Badge),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("Reports", "Reports", Icons.Default.Assessment),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("Customers", "Customers", Icons.Default.PersonSearch),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("Knowledge", "Knowledge Base", Icons.Default.Book),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("Support", "Support Inbox", Icons.Default.Email),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("Services", "Services Master", Icons.Default.Settings),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("Referrals", "Referral Partners", Icons.Default.Share),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("Renewals", "Renewals Hub", Icons.Default.MilitaryTech),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("Recurring", "Recurring Hub", Icons.Default.Loop),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("Bookkeeping", "Bookkeeping Audits", Icons.Default.AccountBalance),
            com.sbr.vrherebms.ui.components.BMSSidebarItem("Settings", "Settings", Icons.Default.SettingsApplications)
        )
    }

    ModalNavigationDrawer(
        drawerState = drawerState,
        drawerContent = {
            com.sbr.vrherebms.ui.components.BMSAppSidebar(
                userName = userName,
                roleName = "System Administrator",
                menuItems = sidebarItems,
                activeTab = activeTab,
                onTabSelected = { activeTab = it },
                onLogout = onLogout,
                onClose = { scope.launch { drawerState.close() } }
            )
        }
    ) {
        Scaffold(
            topBar = {
                Column {
                    com.sbr.vrherebms.ui.components.VRHeader(
                        title = "ADMIN PANEL",
                        showMenu = true,
                        onMenuClick = { scope.launch { drawerState.open() } },
                        showBack = activeTab != "Dashboard" || adminViewModel.selectedOrderId != null,
                        onBackClick = {
                            if (adminViewModel.selectedOrderId != null) {
                                adminViewModel.selectedOrderId = null
                            } else {
                                activeTab = "Dashboard"
                            }
                        },
                        onLogoClick = {
                            adminViewModel.selectedOrderId = null
                            activeTab = "Dashboard"
                        },
                        showNotifications = true,
                        hasUnreadNotifications = adminViewModel.notifications.any { !it.isRead },
                        unreadNotificationsCount = adminViewModel.notifications.count { !it.isRead },
                        onNotificationsClick = { showNotificationsDialog = true },
                        showLogout = true,
                        onLogoutClick = onLogout
                    )
                    if (adminViewModel.isLoading) {
                        LinearProgressIndicator(
                            color = Color(0xFF6366F1),
                            modifier = Modifier.fillMaxWidth().height(2.5.dp)
                        )
                    }
                }
            },
            bottomBar = {
                if (adminViewModel.selectedOrderId == null) {
                    com.sbr.vrherebms.ui.components.BMSAppFloatingDock(
                        activeTab = activeTab,
                        dockItems = dockItems,
                        onTabSelected = { activeTab = it }
                    )
                }
            },
            floatingActionButton = {
                if (adminViewModel.selectedOrderId == null && activeTab == "Dashboard") {
                    com.sbr.vrherebms.ui.components.BMSQuickActionFAB(
                        onNewOrder = { showNewOrderDialog = true },
                        onNewTodo = { showNewTodoDialog = true }
                    )
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
                "Leads", "CRM" -> {
                    AdminCrmScreen(adminViewModel = adminViewModel)
                }
                "Orders" -> {
                    AdminOrdersScreen(adminViewModel = adminViewModel)
                }
                "Blogs" -> {
                    AdminBlogsScreen(adminViewModel = adminViewModel)
                }
                "Offers" -> {
                    AdminOffersScreen(adminViewModel = adminViewModel)
                }
                "Users" -> {
                    AdminUsersScreen(adminViewModel = adminViewModel)
                }
                "Freelancers" -> {
                    AdminFreelancersScreen(adminViewModel = adminViewModel)
                }
                "ToDo", "Todo" -> {
                    AdminTodoScreen(adminViewModel = adminViewModel)
                }
                "Compliance" -> {
                    AdminComplianceScreen(adminViewModel = adminViewModel)
                }
                "ITChecklist" -> {
                    AdminITChecklistScreen(adminViewModel = adminViewModel)
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
                "Customers" -> {
                    AdminCustomersScreen(adminViewModel = adminViewModel)
                }
                "Knowledge", "KB" -> {
                    AdminKbScreen()
                }
                "Support" -> {
                    AdminSupportScreen(adminViewModel = adminViewModel)
                }
                "Services" -> {
                    AdminServicesScreen(adminViewModel = adminViewModel)
                }
                "Referrals", "Referral" -> {
                    AdminReferralScreen(adminViewModel = adminViewModel)
                }
                "Renewals" -> {
                    AdminRenewalsScreen(adminViewModel = adminViewModel)
                }
                "Recurring" -> {
                    AdminRecurringScreen(adminViewModel = adminViewModel)
                }
                "Bookkeeping", "Finance" -> {
                    AdminBookkeepingScreen(adminViewModel = adminViewModel)
                }
                "Notifications" -> {
                    AdminNotificationsScreen(adminViewModel = adminViewModel)
                }
                "Settings" -> {
                    AdminSettingsScreen()
                }
                else -> {
                    AdminHomeTab(
                        adminViewModel = adminViewModel,
                        userName = userName,
                        onOpenNewOrder = { showNewOrderDialog = true },
                        onOpenNewTodo = { showNewTodoDialog = true },
                        onNavigate = { activeTab = it }
                    )
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

    // C. PREMIUM NOTIFICATIONS BOTTOM SHEET WITH NAVIGATION
    if (showNotificationsDialog) {
        ModalBottomSheet(
            onDismissRequest = { showNotificationsDialog = false },
            containerColor = Color.White,
            shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
            dragHandle = { BottomSheetDefaults.DragHandle() }
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .fillMaxHeight(0.85f)
                    .padding(horizontal = 20.dp, vertical = 8.dp)
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
                        Text(
                            text = "Admin Notifications",
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Black,
                            color = textDark
                        )
                        val unreadCount = adminViewModel.notifications.count { !it.isRead }
                        if (unreadCount > 0) {
                            Surface(
                                shape = RoundedCornerShape(12.dp),
                                color = primaryRed.copy(alpha = 0.12f)
                            ) {
                                Text(
                                    text = "$unreadCount new",
                                    color = primaryRed,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                                )
                            }
                        }
                    }

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        if (adminViewModel.notifications.any { !it.isRead }) {
                            TextButton(onClick = { adminViewModel.markAllNotificationsAsRead() }) {
                                Text("Mark all read", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = textDark)
                            }
                        }
                        IconButton(onClick = { showNotificationsDialog = false }) {
                            Icon(Icons.Default.Close, contentDescription = "Close", tint = textMuted)
                        }
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

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
                                imageVector = Icons.Default.NotificationsNone,
                                contentDescription = null,
                                tint = textMuted.copy(alpha = 0.4f),
                                modifier = Modifier.size(56.dp)
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                            Text("All caught up!", color = textDark, fontWeight = FontWeight.Bold, fontSize = 15.sp)
                            Text("No notifications recorded yet.", color = textMuted, fontSize = 12.sp)
                        }
                    }
                } else {
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxWidth()
                            .weight(1f),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        items(notifList) { notif ->
                            val cardBg = if (notif.isRead) Color.White else Color(0xFFF8FAFC)
                            val borderColor = if (notif.isRead) Color(0xFFF1F5F9) else primaryRed.copy(alpha = 0.25f)
                            Card(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        adminViewModel.markNotificationAsRead(notif.id)
                                        showNotificationsDialog = false

                                        // Navigate directly to respective place
                                        val combined = (notif.title + " " + notif.message).lowercase()
                                        val matchedOrder = adminViewModel.orders.find { ord ->
                                            (ord.id.isNotBlank() && combined.contains(ord.id.takeLast(6).lowercase())) ||
                                            (ord.serviceName.isNotBlank() && combined.contains(ord.serviceName.lowercase())) ||
                                            (ord.clientName.isNotBlank() && combined.contains(ord.clientName.lowercase()))
                                        }

                                        if (matchedOrder != null) {
                                            adminViewModel.selectedOrderId = matchedOrder.id
                                            activeTab = "Orders"
                                        } else if (notif.type.equals("Order", ignoreCase = true) || combined.contains("order") || combined.contains("broadcast") || combined.contains("claimed") || combined.contains("work")) {
                                            adminViewModel.selectedOrderId = null
                                            activeTab = "Orders"
                                        } else if (notif.type.equals("Payment", ignoreCase = true) || combined.contains("payment") || combined.contains("invoice")) {
                                            activeTab = "Finance"
                                        } else if (notif.type.equals("Ticket", ignoreCase = true) || combined.contains("ticket") || combined.contains("support")) {
                                            activeTab = "Support"
                                        } else if (combined.contains("lead") || combined.contains("intent") || combined.contains("crm") || combined.contains("prospect")) {
                                            activeTab = "CRM"
                                        } else if (combined.contains("task") || combined.contains("todo")) {
                                            activeTab = "Todo"
                                        } else if (combined.contains("leave") || combined.contains("attendance") || combined.contains("hrms") || combined.contains("employee")) {
                                            activeTab = "HRMS"
                                        } else {
                                            activeTab = "Orders"
                                        }
                                    },
                                colors = CardDefaults.cardColors(containerColor = cardBg),
                                shape = RoundedCornerShape(16.dp),
                                border = BorderStroke(1.dp, borderColor)
                            ) {
                                Row(
                                    modifier = Modifier.padding(14.dp),
                                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                                    verticalAlignment = Alignment.Top
                                ) {
                                    val iconColor = when {
                                        notif.type.equals("Order", true) || notif.title.contains("WORK", true) || notif.title.contains("Order", true) -> Color(0xFF0284C7)
                                        notif.type.equals("Payment", true) || notif.title.contains("Payment", true) -> Color(0xFF16A34A)
                                        notif.type.equals("Ticket", true) || notif.title.contains("Ticket", true) -> Color(0xFFD97706)
                                        else -> primaryRed
                                    }
                                    val iconBg = iconColor.copy(alpha = 0.12f)
                                    Box(
                                        modifier = Modifier
                                            .size(40.dp)
                                            .background(iconBg, CircleShape),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Icon(
                                            imageVector = when {
                                                notif.type.equals("Order", true) || notif.title.contains("WORK", true) || notif.title.contains("Order", true) -> Icons.Default.Work
                                                notif.type.equals("Payment", true) || notif.title.contains("Payment", true) -> Icons.Default.Payments
                                                notif.type.equals("Ticket", true) || notif.title.contains("Ticket", true) -> Icons.Default.ConfirmationNumber
                                                else -> Icons.Default.Notifications
                                            },
                                            contentDescription = null,
                                            tint = iconColor,
                                            modifier = Modifier.size(20.dp)
                                        )
                                    }
                                    Column(modifier = Modifier.weight(1f)) {
                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Text(
                                                text = notif.title,
                                                fontWeight = FontWeight.Bold,
                                                color = textDark,
                                                fontSize = 13.sp,
                                                modifier = Modifier.weight(1f)
                                            )
                                            if (!notif.isRead) {
                                                Box(
                                                    modifier = Modifier
                                                        .size(8.dp)
                                                        .background(primaryRed, CircleShape)
                                                )
                                            }
                                        }
                                        Spacer(modifier = Modifier.height(3.dp))
                                        Text(
                                            text = notif.message,
                                            color = textMuted,
                                            fontSize = 12.sp,
                                            lineHeight = 16.sp
                                        )
                                        Spacer(modifier = Modifier.height(6.dp))
                                        Row(
                                            verticalAlignment = Alignment.CenterVertically,
                                            horizontalArrangement = Arrangement.spacedBy(4.dp)
                                        ) {
                                            Text(
                                                text = "Tap to open details",
                                                color = Color(0xFF6366F1),
                                                fontSize = 10.sp,
                                                fontWeight = FontWeight.SemiBold
                                            )
                                            Icon(
                                                Icons.Default.ChevronRight,
                                                contentDescription = null,
                                                tint = Color(0xFF6366F1),
                                                modifier = Modifier.size(12.dp)
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
}
