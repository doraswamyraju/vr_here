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
    val context = LocalContext.current

    // Webview overlay states for live service mapping
    var webviewUrl by remember { mutableStateOf<String?>(null) }
    var webviewTitle by remember { mutableStateOf<String?>(null) }

    // Native service detail screen and checkout states
    var activeServiceKey by remember { mutableStateOf<String?>(null) }
    var checkoutOrderData by remember { mutableStateOf<com.sbr.vrherebms.data.model.CheckoutOrderResponse?>(null) }
    var checkoutPayloadData by remember { mutableStateOf<com.sbr.vrherebms.data.model.CheckoutPayload?>(null) }

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
                onTabSelected = {
                    activeTab = it
                    // Reset order drilldown when switching tabs
                    if (it != "Orders") {
                        selectedOrderId = ""
                    }
                },
                onLogout = onLogout,
                onCloseDrawer = {
                    scope.launch { drawerState.close() }
                }
            )
        }
    ) {
        Box(modifier = Modifier.fillMaxSize()) {
            Scaffold(
                topBar = {
                    // Exact replication of the React mobile header
                    Column {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(64.dp)
                                .background(Color.White)
                                .padding(horizontal = 16.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            IconButton(
                                onClick = {
                                    scope.launch {
                                        if (drawerState.isClosed) drawerState.open() else drawerState.close()
                                    }
                                },
                                modifier = Modifier
                                    .size(40.dp)
                                    .scaleOnPress()
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Menu,
                                    contentDescription = "Menu",
                                    tint = Color(0xFF475569),
                                    modifier = Modifier.size(24.dp)
                                )
                            }

                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.Center
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(32.dp)
                                        .background(Color(0xFF6366F1), RoundedCornerShape(8.dp)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        text = "VR",
                                        color = Color.White,
                                        fontWeight = FontWeight.Black,
                                        fontSize = 12.sp
                                    )
                                }
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = "DASHBOARD",
                                    color = Color(0xFF1E293B),
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.Black,
                                    letterSpacing = (-0.2).sp
                                )
                            }

                            IconButton(
                                onClick = onLogout,
                                modifier = Modifier
                                    .size(40.dp)
                                    .scaleOnPress()
                            ) {
                                Icon(
                                    imageVector = Icons.Default.ExitToApp,
                                    contentDescription = "Logout",
                                    tint = Color(0xFFEF4444),
                                    modifier = Modifier.size(22.dp)
                                )
                            }
                        }
                        HorizontalDivider(
                            thickness = 1.dp,
                            color = Color(0xFFF1F5F9)
                        )
                    }
                },
                bottomBar = {
                    if (activeServiceKey == null) {
                        // Dribbble-style Floating Glow Island Dock Navigation Bar
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(Color(0xFFF8FAFC))
                                .padding(horizontal = 16.dp, vertical = 12.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(78.dp)
                                    .shadow(
                                        elevation = 16.dp,
                                        shape = RoundedCornerShape(28.dp),
                                        clip = false,
                                        ambientColor = Color(0xFF6366F1).copy(alpha = 0.25f),
                                        spotColor = Color(0xFF6366F1).copy(alpha = 0.5f)
                                    )
                                    .background(Color(0xFF0F172A), RoundedCornerShape(28.dp))
                                    .border(
                                        width = 1.dp,
                                        brush = Brush.horizontalGradient(
                                            colors = listOf(
                                                Color(0xFF6366F1).copy(alpha = 0.4f),
                                                Color(0xFF8B5CF6).copy(alpha = 0.4f),
                                                Color(0xFFEC4899).copy(alpha = 0.15f)
                                            )
                                        ),
                                        shape = RoundedCornerShape(28.dp)
                                    )
                                    .padding(horizontal = 8.dp),
                                horizontalArrangement = Arrangement.SpaceEvenly,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                val navItems = listOf(
                                    Triple("Home", Icons.Default.Dashboard, "Me"),
                                    Triple("Services", Icons.Default.Work, "Services"),
                                    Triple("Orders", Icons.Default.ShoppingBag, "Orders"),
                                    Triple("Invoices", Icons.Default.ReceiptLong, "Invoices"),
                                    Triple("Vault", Icons.Default.Folder, "Docs"),
                                    Triple("Account", Icons.Default.Person, "Account")
                                )

                                navItems.forEach { (tabId, icon, label) ->
                                    val isSelected = activeTab == tabId

                                    val interactionSource = remember { MutableInteractionSource() }
                                    val isPressed by interactionSource.collectIsPressedAsState()

                                    // Dynamic scale springs active tab exactly 30% larger (1.3f)
                                    val scale by animateFloatAsState(
                                        targetValue = if (isSelected) 1.3f else 1.0f,
                                        animationSpec = spring(
                                            dampingRatio = Spring.DampingRatioLowBouncy,
                                            stiffness = Spring.StiffnessMediumLow
                                        ),
                                        label = "NavTabScale"
                                    )

                                    // Translates upwards slightly for a floating physics feel
                                    val translationY by animateFloatAsState(
                                        targetValue = if (isSelected) -6f else 0f,
                                        animationSpec = spring(
                                            dampingRatio = Spring.DampingRatioLowBouncy,
                                            stiffness = Spring.StiffnessMediumLow
                                        ),
                                        label = "NavTabFloat"
                                    )

                                    // Premium hardware-accelerated pressure feedback (shrinks slightly on press)
                                    val pressScale by animateFloatAsState(
                                        targetValue = if (isPressed) 0.92f else 1.0f,
                                        animationSpec = spring(
                                            dampingRatio = Spring.DampingRatioNoBouncy,
                                            stiffness = Spring.StiffnessHigh
                                        ),
                                        label = "NavTabPressScale"
                                    )

                                    // Soft fade transitions between active/inactive item transparency
                                    val alpha by animateFloatAsState(
                                        targetValue = if (isSelected) 1.0f else 0.55f,
                                        animationSpec = tween(durationMillis = 200, easing = LinearOutSlowInEasing),
                                        label = "NavTabAlpha"
                                    )

                                    Box(
                                        modifier = Modifier
                                            .weight(1f)
                                            .fillMaxHeight()
                                            .clickable(
                                                interactionSource = interactionSource,
                                                indication = null
                                            ) {
                                                activeTab = tabId
                                                // Reset order drilldown when switching tabs
                                                if (tabId != "Orders") {
                                                    selectedOrderId = ""
                                                }
                                            }
                                            .graphicsLayer {
                                                scaleX = scale * pressScale
                                                scaleY = scale * pressScale
                                                this.translationY = translationY.dp.toPx()
                                                this.alpha = alpha
                                            },
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Column(
                                            horizontalAlignment = Alignment.CenterHorizontally,
                                            verticalArrangement = Arrangement.Center
                                        ) {
                                            Box(
                                                contentAlignment = Alignment.Center,
                                                modifier = Modifier.size(32.dp)
                                            ) {
                                                // Blooming radial glow aura in the background of the active tab
                                                androidx.compose.animation.AnimatedVisibility(
                                                    visible = isSelected,
                                                    enter = fadeIn(animationSpec = tween(200)) + scaleIn(
                                                        animationSpec = spring(
                                                            dampingRatio = Spring.DampingRatioLowBouncy,
                                                            stiffness = Spring.StiffnessMediumLow
                                                        )
                                                    ),
                                                    exit = fadeOut(animationSpec = tween(150)) + scaleOut()
                                                ) {
                                                    Box(
                                                        modifier = Modifier
                                                            .size(28.dp)
                                                            .background(
                                                                brush = Brush.radialGradient(
                                                                    colors = listOf(
                                                                        Color(0xFF6366F1).copy(alpha = 0.5f),
                                                                        Color(0xFF8B5CF6).copy(alpha = 0.2f),
                                                                        Color.Transparent
                                                                    )
                                                                ),
                                                                shape = CircleShape
                                                            )
                                                    )
                                                }

                                                Icon(
                                                    imageVector = icon,
                                                    contentDescription = label,
                                                    tint = if (isSelected) Color.White else Color(0xFF94A3B8),
                                                    modifier = Modifier.size(20.dp)
                                                )
                                            }

                                            // Text name expands vertically with slide-in transition
                                            androidx.compose.animation.AnimatedVisibility(
                                                visible = isSelected,
                                                enter = expandVertically(
                                                    expandFrom = Alignment.Top,
                                                    animationSpec = spring(
                                                        dampingRatio = Spring.DampingRatioLowBouncy,
                                                        stiffness = Spring.StiffnessMediumLow
                                                    )
                                                ) + fadeIn(animationSpec = tween(150)),
                                                exit = shrinkVertically(
                                                    shrinkTowards = Alignment.Top,
                                                    animationSpec = spring(
                                                        dampingRatio = Spring.DampingRatioNoBouncy,
                                                        stiffness = Spring.StiffnessMedium
                                                    )
                                                ) + fadeOut(animationSpec = tween(100))
                                            ) {
                                                Column(
                                                    horizontalAlignment = Alignment.CenterHorizontally,
                                                    modifier = Modifier.padding(top = 1.dp)
                                                ) {
                                                    Text(
                                                        text = label,
                                                        color = Color.White,
                                                        fontSize = 8.5.sp, // scaled up by 1.3 becomes ~11.sp
                                                        fontWeight = FontWeight.Black,
                                                        letterSpacing = 0.3.sp,
                                                        maxLines = 1
                                                    )
                                                    Spacer(modifier = Modifier.height(3.dp))
                                                    // Neon dot/capsule indicator at the bottom of the active tab
                                                    Box(
                                                        modifier = Modifier
                                                            .width(10.dp)
                                                            .height(3.dp)
                                                            .background(
                                                                brush = Brush.horizontalGradient(
                                                                    colors = listOf(Color(0xFF6366F1), Color(0xFF8B5CF6))
                                                                ),
                                                                shape = RoundedCornerShape(1.5.dp)
                                                            )
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
                            "Invoices" -> CustomerInvoicesTab(viewModel)
                            "Vault" -> CustomerVaultTab(viewModel)
                            "Support" -> CustomerSupportTab(viewModel)
                            "Account" -> CustomerAccountTab(
                                viewModel = viewModel,
                                onSelectTab = { activeTab = it }
                            )
                        }
                    }

                    // Persistence of WhatsApp & Support Ticket floating triggers exactly like the React page
                    Column(
                        modifier = Modifier
                            .align(Alignment.BottomEnd)
                            .padding(end = 20.dp, bottom = 24.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                        horizontalAlignment = Alignment.End
                    ) {
                        // WhatsApp Launcher
                        Box(
                            modifier = Modifier
                                .size(52.dp)
                                .background(Color(0xFF10B981), CircleShape)
                                .shadow(8.dp, CircleShape)
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
                                modifier = Modifier.size(24.dp)
                            )
                        }

                        // Support Ticket Launcher
                        Box(
                            modifier = Modifier
                                .size(52.dp)
                                .background(Color(0xFF6366F1), CircleShape)
                                .shadow(8.dp, CircleShape)
                                .scaleOnPress()
                                .clickable { activeTab = "Support" },
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.HeadsetMic,
                                contentDescription = "Support",
                                tint = Color.White,
                                modifier = Modifier.size(24.dp)
                            )
                        }
                    }
                }
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
                                        checkoutPayloadData = payload
                                        checkoutOrderData = checkoutResponse.body()
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
}
