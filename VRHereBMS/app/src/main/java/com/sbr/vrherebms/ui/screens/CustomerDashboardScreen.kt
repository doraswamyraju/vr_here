package com.sbr.vrherebms.ui.screens

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.animation.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.automirrored.filled.ReceiptLong
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.animation.core.*
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.ui.screens.customer.*
import com.sbr.vrherebms.ui.components.*
import com.sbr.vrherebms.ui.theme.*
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel
import com.sbr.vrherebms.data.remote.VRHereAPI
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomerDashboardScreen(
    viewModel: CustomerDashboardViewModel,
    userName: String,
    onLogout: () -> Unit
) {
    var activeTab by remember { mutableStateOf("Home") }
    var selectedOrderId by remember { mutableStateOf("") }
    var searchQuery by remember { mutableStateOf("") }
    var isShowingNotifications by remember { mutableStateOf(false) }
    var isShowingMenuSheet by remember { mutableStateOf(false) }
    val context = LocalContext.current

    // Webview overlay states for live service mapping
    var webviewUrl by remember { mutableStateOf<String?>(null) }
    var webviewTitle by remember { mutableStateOf<String?>(null) }

    // Native service detail screen and checkout states
    var activeServiceKey by remember { mutableStateOf<String?>(null) }
    var checkoutOrderData by remember { mutableStateOf<com.sbr.vrherebms.data.model.CheckoutOrderResponse?>(null) }
    var checkoutPayloadData by remember { mutableStateOf<com.sbr.vrherebms.data.model.CheckoutPayload?>(null) }

    var showLogoutDialog by remember { mutableStateOf(false) }

    val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)
    val scope = rememberCoroutineScope()

    LaunchedEffect(key1 = true) {
        // Initial full-screen load
        viewModel.refreshAllData(silent = false)

        // Silent periodic background polling every 15 seconds
        launch {
            while (true) {
                kotlinx.coroutines.delay(15000)
                viewModel.refreshAllData(silent = true)
            }
        }

        // Fetch Dynamic Service Page configs on boot from the server database
        launch {
            try {
                val apiService = VRHereAPI.getInstance(context)
                val response = apiService.getDynamicServices()
                if (response.isSuccessful && response.body() != null) {
                    ServiceCatalog.updateFromApi(response.body()!!)
                }
            } catch (e: Exception) {
                android.util.Log.e("ServiceCatalog", "Failed loading dynamic catalog sync", e)
            }
        }

        viewModel.eventFlow.collect { event ->
            if (event is CustomerDashboardViewModel.UiEvent.ShowToast) {
                Toast.makeText(context, event.message, Toast.LENGTH_SHORT).show()
            }
        }
    }

    val lightSlate = Color(0xFFF8FAFC)

    ModalNavigationDrawer(
        drawerState = drawerState,
        drawerContent = {
            CustomerSidebarContent(
                userName = userName,
                activeTab = activeTab,
                profilePhoto = viewModel.profilePhoto,
                companyName = viewModel.companyName,
                activeOrdersCount = viewModel.orders.filter { it.status != "Completed" }.size,
                unreadNotificationsCount = viewModel.notifications.filter { !it.isRead }.size,
                onTabSelected = {
                    activeTab = it
                    // Reset order drilldown when switching tabs
                    if (it != "Orders") {
                        selectedOrderId = ""
                    }
                },
                onLogout = {
                    scope.launch { drawerState.close() }
                    showLogoutDialog = true
                },
                onCloseDrawer = {
                    scope.launch { drawerState.close() }
                }
            )
        }
    ) {
        Box(modifier = Modifier.fillMaxSize()) {
            Scaffold(
                topBar = {
                    VRHeader(
                        title = "DASHBOARD",
                        showMenu = true,
                        onMenuClick = {
                            scope.launch {
                                if (drawerState.isClosed) drawerState.open() else drawerState.close()
                            }
                        },
                        showBack = false,
                        onBackClick = { activeTab = "Home" },
                        onLogoClick = {
                            activeTab = "Home"
                            selectedOrderId = ""
                        },
                        showNotifications = true,
                        hasUnreadNotifications = viewModel.notifications.any { !it.isRead },
                        onNotificationsClick = { isShowingNotifications = true },
                        showLogout = true,
                        onLogoutClick = { showLogoutDialog = true },
                        userProfilePhoto = viewModel.profilePhoto,
                        userName = userName,
                        onProfileClick = { activeTab = "Account" }
                    )
                },
                bottomBar = {
                    if (activeServiceKey == null) {
                        BMSAppBottomNavBar(
                            activeTab = activeTab,
                            onTabSelected = { tabId ->
                                activeTab = tabId
                                if (tabId != "Orders") {
                                    selectedOrderId = ""
                                }
                            },
                            onOpenMenuSheet = {
                                isShowingMenuSheet = true
                            }
                        )
                    }
                }
            ) { paddingValues ->
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(paddingValues)
                        .background(lightSlate)
                ) {
                    AnimatedContent(
                        targetState = activeTab,
                        transitionSpec = {
                            fadeIn() togetherWith fadeOut()
                        },
                        label = "TabContent"
                    ) { targetTab ->
                        when (targetTab) {
                            "Home" -> CustomerHomeTab(
                                viewModel = viewModel,
                                userName = userName,
                                searchQuery = searchQuery,
                                onSearchQueryChange = { searchQuery = it },
                                onSelectTab = { activeTab = it },
                                onOpenProject = { orderId ->
                                    selectedOrderId = orderId
                                    activeTab = "Orders"
                                },
                                onOpenLiveService = { name, url ->
                                    val key = url.substringAfterLast("/")
                                    if (key in ServiceCatalog.items.keys) {
                                        activeServiceKey = key
                                    } else {
                                        webviewUrl = url
                                        webviewTitle = name
                                    }
                                }
                            )
                            "Services" -> CustomerServicesTab(
                                viewModel = viewModel,
                                onSelectTab = { activeTab = it },
                                onOpenLiveService = { name, url ->
                                    val key = url.substringAfterLast("/")
                                    if (key in ServiceCatalog.items.keys) {
                                        activeServiceKey = key
                                    } else {
                                        webviewUrl = url
                                        webviewTitle = name
                                    }
                                }
                            )
                            "Orders" -> CustomerOrdersTab(
                                viewModel = viewModel,
                                selectedOrderId = selectedOrderId,
                                onSelectOrderId = { selectedOrderId = it },
                                onSelectTab = { activeTab = it }
                            )
                            "Referrals" -> CustomerReferralTab()
                            "Invoices" -> CustomerInvoicesTab(viewModel)
                            "Vault" -> CustomerVaultTab(viewModel)
                            "Bookkeeping" -> BookkeepingScreen(viewModel)
                            "Support" -> CustomerSupportTab(viewModel)
                            "Account" -> CustomerAccountTab(
                                viewModel = viewModel,
                                onSelectTab = { activeTab = it }
                            )
                        }
                    }

                    // Persistence of WhatsApp & Direct Call floating triggers
                    Column(
                        modifier = Modifier
                            .align(Alignment.BottomEnd)
                            .padding(end = 16.dp, bottom = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                        horizontalAlignment = Alignment.End
                    ) {
                        // WhatsApp Launcher
                        Box(
                            modifier = Modifier
                                .size(48.dp)
                                .background(Color(0xFF22C55E), CircleShape)
                                .shadow(6.dp, CircleShape, ambientColor = Color(0xFF22C55E).copy(alpha = 0.3f))
                                .scaleOnPress()
                                .clickable {
                                    try {
                                        val url = "https://wa.me/918008530606"
                                        val i = Intent(Intent.ACTION_VIEW)
                                        i.data = Uri.parse(url)
                                        context.startActivity(i)
                                    } catch (e: Exception) {
                                        Toast.makeText(context, "WhatsApp not found", Toast.LENGTH_SHORT).show()
                                    }
                                },
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.Chat,
                                contentDescription = "WhatsApp Chat",
                                tint = Color.White,
                                modifier = Modifier.size(22.dp)
                            )
                        }

                        // Direct Phone Call Launcher
                        Box(
                            modifier = Modifier
                                .size(48.dp)
                                .background(
                                    Brush.linearGradient(
                                        listOf(Indigo500, Indigo600)
                                    ),
                                    CircleShape
                                )
                                .shadow(6.dp, CircleShape, ambientColor = Indigo500.copy(alpha = 0.4f))
                                .scaleOnPress()
                                .clickable {
                                    try {
                                        val intent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:918008530606"))
                                        context.startActivity(intent)
                                    } catch (e: Exception) {
                                        Toast.makeText(context, "Dialer not available", Toast.LENGTH_SHORT).show()
                                    }
                                },
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.Phone,
                                contentDescription = "Direct Call",
                                tint = Color.White,
                                modifier = Modifier.size(20.dp)
                            )
                        }
                    }
                }
            }

            // Notifications Sheet Modal
            if (isShowingNotifications) {
                NotificationsSheet(
                    notifications = viewModel.notifications,
                    onMarkAsRead = { notificationId ->
                        viewModel.markNotificationAsRead(notificationId)
                    },
                    onDismiss = { isShowingNotifications = false }
                )
            }

            // Workspace Hub Bottom Sheet Menu (opened via swipe up or Hub center button)
            if (isShowingMenuSheet) {
                BMSBottomSheetMenuView(
                    userName = userName,
                    activeTab = activeTab,
                    profilePhoto = viewModel.profilePhoto,
                    companyName = viewModel.companyName,
                    onDismissRequest = { isShowingMenuSheet = false },
                    onSelectTab = { tabId ->
                        activeTab = tabId
                        if (tabId != "Orders") {
                            selectedOrderId = ""
                        }
                    },
                    onLogout = onLogout
                )
            }

            // High-fidelity webview overlay for secure in-app checkout payments (Razorpay)
            AnimatedVisibility(
                visible = webviewUrl != null,
                enter = slideInVertically(
                    initialOffsetY = { it },
                    animationSpec = spring(
                        dampingRatio = Spring.DampingRatioLowBouncy,
                        stiffness = Spring.StiffnessMediumLow
                    )
                ) + fadeIn(),
                exit = slideOutVertically(
                    targetOffsetY = { it },
                    animationSpec = spring(
                        dampingRatio = Spring.DampingRatioNoBouncy,
                        stiffness = Spring.StiffnessMedium
                    )
                ) + fadeOut(),
                modifier = Modifier.fillMaxSize()
            ) {
                webviewUrl?.let { url ->
                    CustomerServiceWebView(
                        url = url,
                        title = webviewTitle ?: "Service Details",
                        onClose = {
                            webviewUrl = null
                            webviewTitle = null
                        }
                    )
                }
            }

            // Native high-fidelity Service Detail screen overlay
            AnimatedVisibility(
                visible = activeServiceKey != null,
                enter = slideInHorizontally(
                    initialOffsetX = { it },
                    animationSpec = spring(
                        dampingRatio = Spring.DampingRatioLowBouncy,
                        stiffness = Spring.StiffnessMediumLow
                    )
                ) + fadeIn(),
                exit = slideOutHorizontally(
                    targetOffsetX = { it },
                    animationSpec = spring(
                        dampingRatio = Spring.DampingRatioNoBouncy,
                        stiffness = Spring.StiffnessMedium
                    )
                ) + fadeOut(),
                modifier = Modifier.fillMaxSize()
            ) {
                activeServiceKey?.let { key ->
                    CustomerServiceDetailScreen(
                        serviceKey = key,
                        onBackClick = { activeServiceKey = null },
                        onNeedAdviceClick = {
                            activeServiceKey = null
                            activeTab = "Support"
                        },
                        onCheckoutClick = { serviceTitle, selectedPlan, name, email, phone ->
                            scope.launch {
                                Toast.makeText(context, "Initiating order checkout...", Toast.LENGTH_SHORT).show()
                                val payload = com.sbr.vrherebms.data.model.CheckoutPayload(
                                    serviceName = serviceTitle,
                                    packageName = selectedPlan.name,
                                    amount = selectedPlan.price,
                                    customerName = name,
                                    email = email,
                                    phone = phone
                                )
                                try {
                                    val apiService = VRHereAPI.getInstance(context)
                                    val checkoutResponse = apiService.checkoutOrder(payload)
                                    if (checkoutResponse.isSuccessful && checkoutResponse.body() != null) {
                                        val orderData = checkoutResponse.body()!!
                                        val activity = context as? android.app.Activity
                                        if (activity != null) {
                                            com.sbr.vrherebms.utils.RazorpayManager.startPayment(
                                                activity = activity,
                                                key = orderData.key,
                                                orderId = orderData.orderId,
                                                amount = orderData.amount,
                                                currency = orderData.currency,
                                                serviceName = payload.serviceName,
                                                packageName = payload.packageName,
                                                customerName = payload.customerName,
                                                customerEmail = payload.email,
                                                customerPhone = payload.phone,
                                                onSuccess = { paymentId, ordId, signature ->
                                                    scope.launch {
                                                        Toast.makeText(context, "Payment successful! Verifying transaction...", Toast.LENGTH_LONG).show()
                                                        val verifyPayload = com.sbr.vrherebms.data.model.VerifyPayload(
                                                            serviceName = payload.serviceName,
                                                            packageName = payload.packageName,
                                                            amount = payload.amount,
                                                            customerName = payload.customerName,
                                                            email = payload.email,
                                                            phone = payload.phone,
                                                            razorpay_order_id = ordId.ifBlank { orderData.orderId },
                                                            razorpay_payment_id = paymentId,
                                                            razorpay_signature = signature
                                                        )
                                                        try {
                                                            val verifyResponse = apiService.verifyPayment(verifyPayload)
                                                            if (verifyResponse.isSuccessful && verifyResponse.body()?.success == true) {
                                                                Toast.makeText(context, "Compliance Order Registered Successfully!", Toast.LENGTH_LONG).show()
                                                                activeServiceKey = null
                                                                viewModel.refreshAllData()
                                                                activeTab = "Orders"
                                                            } else {
                                                                val errorMsg = verifyResponse.body()?.message ?: "Signature verification failed"
                                                                Toast.makeText(context, "Verification Error: $errorMsg", Toast.LENGTH_LONG).show()
                                                            }
                                                        } catch (e: Exception) {
                                                            Toast.makeText(context, "Network Error: ${e.localizedMessage}", Toast.LENGTH_LONG).show()
                                                        }
                                                    }
                                                },
                                                onFailure = { errorMsg ->
                                                    Toast.makeText(context, "Payment cancelled / failed: $errorMsg", Toast.LENGTH_LONG).show()
                                                }
                                            )
                                        } else {
                                            checkoutPayloadData = payload
                                            checkoutOrderData = orderData
                                        }
                                    } else {
                                        val errorMsg = checkoutResponse.errorBody()?.string() ?: "Failed to generate checkout order"
                                        Toast.makeText(context, errorMsg, Toast.LENGTH_LONG).show()
                                    }
                                } catch (e: Exception) {
                                    Toast.makeText(context, "Connection error: ${e.localizedMessage}", Toast.LENGTH_LONG).show()
                                }
                            }
                        }
                    )
                }
            }

            // High-fidelity WebView overlay for Razorpay Payment
            AnimatedVisibility(
                visible = checkoutOrderData != null,
                enter = slideInVertically(
                    initialOffsetY = { it },
                    animationSpec = spring(
                        dampingRatio = Spring.DampingRatioLowBouncy,
                        stiffness = Spring.StiffnessMediumLow
                    )
                ) + fadeIn(),
                exit = slideOutVertically(
                    targetOffsetY = { it },
                    animationSpec = spring(
                        dampingRatio = Spring.DampingRatioNoBouncy,
                        stiffness = Spring.StiffnessMedium
                    )
                ) + fadeOut(),
                modifier = Modifier.fillMaxSize()
            ) {
                val orderData = checkoutOrderData
                val payload = checkoutPayloadData
                if (orderData != null && payload != null) {
                    CustomerPaymentWebView(
                        key = orderData.key,
                        orderId = orderData.orderId,
                        amount = orderData.amount,
                        currency = orderData.currency,
                        serviceName = payload.serviceName,
                        packageName = payload.packageName,
                        customerName = payload.customerName,
                        customerEmail = payload.email,
                        customerPhone = payload.phone,
                        onSuccess = { paymentId, ordId, signature ->
                            checkoutOrderData = null
                            checkoutPayloadData = null
                            activeServiceKey = null
                            
                            scope.launch {
                                Toast.makeText(context, "Payment successful! Verifying transaction...", Toast.LENGTH_LONG).show()
                                val verifyPayload = com.sbr.vrherebms.data.model.VerifyPayload(
                                    serviceName = payload.serviceName,
                                    packageName = payload.packageName,
                                    amount = payload.amount,
                                    customerName = payload.customerName,
                                    email = payload.email,
                                    phone = payload.phone,
                                    razorpay_order_id = ordId,
                                    razorpay_payment_id = paymentId,
                                    razorpay_signature = signature
                                )
                                try {
                                    val apiService = VRHereAPI.getInstance(context)
                                    val verifyResponse = apiService.verifyPayment(verifyPayload)
                                    if (verifyResponse.isSuccessful && verifyResponse.body()?.success == true) {
                                        Toast.makeText(context, "Compliance Order Registered Successfully!", Toast.LENGTH_LONG).show()
                                        // Refresh all data on dashboard
                                        viewModel.refreshAllData()
                                        // Route to orders page
                                        activeTab = "Orders"
                                    } else {
                                        val errorMsg = verifyResponse.body()?.message ?: "Signature verification failed"
                                        Toast.makeText(context, "Verification Error: $errorMsg", Toast.LENGTH_LONG).show()
                                    }
                                } catch (e: Exception) {
                                    Toast.makeText(context, "Network Error: ${e.localizedMessage}", Toast.LENGTH_LONG).show()
                                }
                            }
                        },
                        onFailure = { errorMsg ->
                            checkoutOrderData = null
                            checkoutPayloadData = null
                            Toast.makeText(context, "Payment failed: $errorMsg", Toast.LENGTH_LONG).show()
                        },
                        onClose = {
                            checkoutOrderData = null
                            checkoutPayloadData = null
                            Toast.makeText(context, "Payment closed", Toast.LENGTH_SHORT).show()
                        }
                    )
                }
            }

            // Lockscreen-style Heads-up In-app Notification Banner
            AnimatedVisibility(
                visible = viewModel.activeBannerNotification != null,
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
                    .padding(top = 48.dp, start = 16.dp, end = 16.dp)
                    .fillMaxWidth()
                    .wrapContentHeight()
            ) {
                viewModel.activeBannerNotification?.let { notif ->
                    LaunchedEffect(notif.id) {
                        kotlinx.coroutines.delay(5000)
                        viewModel.dismissBanner()
                    }

                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .shadow(24.dp, RoundedCornerShape(20.dp))
                            .clickable {
                                viewModel.dismissBanner()
                                activeTab = "Home"
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
                                        text = "VR Here Business Management Solutions", 
                                        color = Color(0xFF818CF8),
                                        fontSize = 9.sp, 
                                        fontWeight = FontWeight.Black, 
                                        letterSpacing = 0.2.sp
                                    )
                                    Text(
                                        text = "• Just now", 
                                        color = Color(0xFF94A3B8), 
                                        fontSize = 10.sp, 
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                                IconButton(
                                    onClick = { viewModel.dismissBanner() },
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

    if (showLogoutDialog) {
        AlertDialog(
            onDismissRequest = { showLogoutDialog = false },
            title = {
                Text(
                    text = "Sign Out",
                    fontWeight = FontWeight.Bold,
                    color = TextDark
                )
            },
            text = {
                Text(
                    text = "Are you sure you want to sign out of VR Here?",
                    color = TextMuted,
                    fontSize = 14.sp
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        showLogoutDialog = false
                        onLogout()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = PrimaryRed)
                ) {
                    Text("Sign Out", color = Color.White, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showLogoutDialog = false }) {
                    Text("Cancel", color = Slate600, fontWeight = FontWeight.SemiBold)
                }
            },
            containerColor = Color.White,
            shape = RoundedCornerShape(16.dp)
        )
    }
}
