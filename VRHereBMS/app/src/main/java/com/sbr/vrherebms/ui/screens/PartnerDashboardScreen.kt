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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
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
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.*
import com.sbr.vrherebms.viewmodel.PartnerDashboardViewModel
import com.sbr.vrherebms.viewmodel.PartnerDashboardState
import java.text.NumberFormat
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PartnerDashboardScreen(
    viewModel: PartnerDashboardViewModel,
    userName: String,
    onLogout: () -> Unit
) {
    var activeTab by remember { mutableStateOf("Overview") }
    var searchTerm by remember { mutableStateOf("") }
    val context = LocalContext.current

    LaunchedEffect(key1 = true) {
        viewModel.refreshAllData()
        viewModel.eventFlow.collect { event ->
            when (event) {
                is PartnerDashboardViewModel.UiEvent.ShowToast -> {
                    Toast.makeText(context, event.message, Toast.LENGTH_SHORT).show()
                }
                is PartnerDashboardViewModel.UiEvent.ProfileUpdated -> {
                    // Profile updated successfully
                }
            }
        }
    }

    val primaryGradient = listOf(Color(0xFFF59E0B), Color(0xFFD97706)) // Amber-orange for Partner portal
    val darkSlate = Color(0xFF0F172A)
    val lightSlate = Color(0xFFF8FAFC)

    Scaffold(
        topBar = {
            // Exact replication of React Partner Mobile Header
            Column {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(72.dp)
                        .background(Color.White)
                        .padding(horizontal = 16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconButton(
                        onClick = {
                            Toast.makeText(context, "Partner drawer navigation", Toast.LENGTH_SHORT).show()
                        },
                        modifier = Modifier.size(44.dp)
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
                                .size(36.dp)
                                .background(Color(0xFF0F172A), RoundedCornerShape(10.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "VR",
                                color = Color.White,
                                fontWeight = FontWeight.Black,
                                fontSize = 14.sp
                            )
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = "VR HERE",
                                    color = Color(0xFF0F172A),
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.Black,
                                    letterSpacing = 0.5.sp
                                )
                                Spacer(modifier = Modifier.width(4.dp))
                                Box(
                                    modifier = Modifier
                                        .size(5.dp)
                                        .background(Color(0xFFF59E0B), CircleShape)
                                )
                            }
                            Text(
                                text = "PARTNER PORTAL",
                                color = Color(0xFFEF4444),
                                fontSize = 8.sp,
                                fontWeight = FontWeight.Black,
                                letterSpacing = 0.5.sp
                            )
                        }
                    }

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        // Bell Notification Icon with red dot badge
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .clip(RoundedCornerShape(10.dp))
                                .clickable {
                                    Toast.makeText(context, "No new alerts", Toast.LENGTH_SHORT).show()
                                },
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.Notifications,
                                contentDescription = "Alerts",
                                tint = Color(0xFF94A3B8),
                                modifier = Modifier.size(22.dp)
                            )
                            // Red dot badge
                            Box(
                                modifier = Modifier
                                    .size(8.dp)
                                    .background(Color(0xFFEF4444), CircleShape)
                                    .border(1.5.dp, Color.White, CircleShape)
                                    .align(Alignment.TopEnd)
                                    .offset(x = (-8).dp, y = 8.dp)
                            )
                        }

                        // User Avatar
                        Box(
                            modifier = Modifier
                                .size(36.dp)
                                .background(Color(0xFF0F172A), RoundedCornerShape(10.dp))
                                .clickable {
                                    // Let user sign out when clicking avatar
                                    Toast.makeText(context, "Signing out...", Toast.LENGTH_SHORT).show()
                                    onLogout()
                                },
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = userName.firstOrNull()?.toString()?.uppercase() ?: "P",
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 14.sp
                            )
                        }
                    }
                }
                HorizontalDivider(
                    thickness = 1.dp,
                    color = Color(0xFFF1F5F9)
                )
            }
        },
        bottomBar = {
            // Replicate the custom dark, rounded, floating bottom navigation from React mobile view
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
                        .height(64.dp)
                        .background(Color(0xFA0F172A), RoundedCornerShape(28.dp))
                        .border(1.dp, Color(0xFFFFFFFF).copy(alpha = 0.15f), RoundedCornerShape(28.dp))
                        .padding(horizontal = 8.dp),
                    horizontalArrangement = Arrangement.SpaceAround,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    val navItems = listOf(
                        Triple("Overview", Icons.Default.Dashboard, "Me"),
                        Triple("Referrals", Icons.Default.People, "Referrals"),
                        Triple("Earnings", Icons.Default.CurrencyRupee, "Earnings"),
                        Triple("Settings", Icons.Default.Settings, "Settings")
                    )

                    navItems.forEach { (tabId, icon, label) ->
                        val isSelected = activeTab == tabId
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(16.dp))
                                .clickable { activeTab = tabId }
                                .padding(vertical = 6.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.Center
                        ) {
                            Icon(
                                imageVector = icon,
                                contentDescription = label,
                                tint = if (isSelected) Color(0xFFF59E0B) else Color(0xFF94A3B8),
                                modifier = Modifier
                                    .size(20.dp)
                                    .animateContentSize()
                            )
                            Spacer(modifier = Modifier.height(3.dp))
                            Text(
                                text = label,
                                fontSize = 8.sp,
                                fontWeight = FontWeight.Black,
                                color = if (isSelected) Color.White else Color(0xFF94A3B8).copy(alpha = 0.7f),
                                letterSpacing = 0.5.sp
                            )
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
            if (viewModel.dashboardState is PartnerDashboardState.Loading) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        CircularProgressIndicator(color = Color(0xFFF59E0B))
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            "Loading dashboard data...",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF64748B)
                        )
                    }
                }
            } else {
                AnimatedContent(
                    targetState = activeTab,
                    transitionSpec = {
                        fadeIn() togetherWith fadeOut()
                    },
                    label = "PartnerTabContent"
                ) { targetTab ->
                    when (targetTab) {
                        "Overview" -> PartnerOverviewTab(viewModel, userName, onSelectTab = { activeTab = it })
                        "Referrals" -> PartnerReferralsTab(viewModel, searchTerm, onSearchTermChange = { searchTerm = it })
                        "Earnings" -> PartnerEarningsTab(viewModel)
                        "Settings" -> PartnerSettingsTab(viewModel)
                    }
                }
            }

            // WhatsApp Support Trigger floating button
            Box(
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(end = 20.dp, bottom = 24.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(52.dp)
                        .background(Color(0xFF10B981), CircleShape)
                        .shadow(8.dp, CircleShape)
                        .clickable {
                            try {
                                val url = "https://wa.me/918008530606"
                                val i = Intent(Intent.ACTION_VIEW)
                                i.data = Uri.parse(url)
                                context.startActivity(i)
                            } catch (e: Exception) {
                                Toast.makeText(context, "WhatsApp not installed", Toast.LENGTH_SHORT).show()
                            }
                        },
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.SupportAgent,
                        contentDescription = "WhatsApp Support",
                        tint = Color.White,
                        modifier = Modifier.size(24.dp)
                    )
                }
            }
        }
    }
}

// --- OVERVIEW TAB ---
@Composable
fun PartnerOverviewTab(
    viewModel: PartnerDashboardViewModel,
    userName: String,
    onSelectTab: (String) -> Unit
) {
    val profile = viewModel.profile
    val orders = viewModel.orders
    val context = LocalContext.current

    val isActive = profile?.isActive == true

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Validation Banner if NOT active
        if (!isActive) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            brush = Brush.linearGradient(listOf(Color(0xFFEF4444), Color(0xFFB91C1C))),
                            shape = RoundedCornerShape(24.dp)
                        )
                        .padding(20.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.Top,
                        horizontalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(44.dp)
                                .background(Color.White.copy(alpha = 0.2f), RoundedCornerShape(12.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.Warning, contentDescription = null, tint = Color.White)
                        }
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                "Account Pending Validation",
                                color = Color.White,
                                fontWeight = FontWeight.Black,
                                fontSize = 16.sp
                            )
                            Text(
                                "Welcome to VR HERE Partner Program! Your account is currently under KYC review. You will start earning commissions once your account is validated by our admin team.",
                                color = Color(0xFFFEE2E2),
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Medium,
                                modifier = Modifier.padding(top = 4.dp)
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                            Box(
                                modifier = Modifier
                                    .background(Color.White.copy(alpha = 0.15f), RoundedCornerShape(8.dp))
                                    .padding(horizontal = 10.dp, vertical = 6.dp)
                            ) {
                                Text(
                                    "24-48 Hours ETA",
                                    color = Color.White,
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Black
                                )
                            }
                        }
                    }
                }
            }
        } else {
            // Success Greeting Banner
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            brush = Brush.linearGradient(listOf(Color(0xFF0F172A), Color(0xFF1E293B))),
                            shape = RoundedCornerShape(24.dp)
                        )
                        .padding(20.dp)
                ) {
                    Column {
                        Text(
                            "Welcome Back, ${userName.split(" ").firstOrNull() ?: userName}",
                            color = Color.White,
                            fontWeight = FontWeight.Black,
                            fontSize = 20.sp
                        )
                        Text(
                            "Monitor your referrals and track your commission earnings seamlessly.",
                            color = Color(0xFF94A3B8),
                            fontSize = 12.sp,
                            modifier = Modifier.padding(top = 4.dp)
                        )
                    }
                }
            }
        }

        // Stats grid
        item {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    PartnerStatCard(
                        modifier = Modifier.weight(1f),
                        title = "Total Referrals",
                        value = orders.size.toString(),
                        label = "Direct Reach",
                        icon = Icons.Default.Group,
                        iconBg = Color(0xFFEEF2F6),
                        iconColor = Color(0xFF4F46E5)
                    )
                    PartnerStatCard(
                        modifier = Modifier.weight(1f),
                        title = "Active Cases",
                        value = orders.filter { it.status != "Completed" }.size.toString(),
                        label = "In Progress",
                        icon = Icons.Default.PendingActions,
                        iconBg = Color(0xFFFEF2F2),
                        iconColor = Color(0xFFEF4444)
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    val totalCommission = orders.sumOf { it.partnerCommissionAmount }
                    PartnerStatCard(
                        modifier = Modifier.weight(1f),
                        title = "Total Commission",
                        value = formatINR(totalCommission),
                        label = "Lifetime Earnings",
                        icon = Icons.Default.CurrencyRupee,
                        iconBg = Color(0xFFECFDF5),
                        iconColor = Color(0xFF10B981)
                    )
                    PartnerStatCard(
                        modifier = Modifier.weight(1f),
                        title = "Conversion Rate",
                        value = if (orders.isNotEmpty()) "100%" else "0%",
                        label = "Paid Referrals",
                        icon = Icons.Default.TrendingUp,
                        iconBg = Color(0xFFFFFBEB),
                        iconColor = Color(0xFFF59E0B)
                    )
                }
            }
        }

        // Quick Actions or Status Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(modifier = Modifier.padding(18.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column {
                            Text(
                                "Partner Status",
                                fontWeight = FontWeight.Black,
                                fontSize = 14.sp,
                                color = Color(0xFF1E293B)
                            )
                            Text(
                                if (isActive) "KYC Verified & Active" else "Pending Verification",
                                fontSize = 11.sp,
                                color = Color(0xFF64748B)
                            )
                        }
                        Box(
                            modifier = Modifier
                                .background(
                                    if (isActive) Color(0xFFD1FAE5) else Color(0xFFFEE2E2),
                                    RoundedCornerShape(8.dp)
                                )
                                .padding(horizontal = 10.dp, vertical = 6.dp)
                        ) {
                            Text(
                                if (isActive) "ACTIVE" else "PENDING",
                                color = if (isActive) Color(0xFF065F46) else Color(0xFF991B1B),
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Black
                            )
                        }
                    }
                }
            }
        }

        // Payout Info Card
        item {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        brush = Brush.linearGradient(listOf(Color(0xFF4F46E5), Color(0xFF3730A3))),
                        shape = RoundedCornerShape(24.dp)
                    )
                    .padding(20.dp)
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Box(
                        modifier = Modifier
                            .size(36.dp)
                            .background(Color.White.copy(alpha = 0.15f), RoundedCornerShape(10.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(Icons.Default.Info, contentDescription = null, tint = Color.White)
                    }
                    Text(
                        "Payment Cycle Info",
                        color = Color.White,
                        fontWeight = FontWeight.Black,
                        fontSize = 16.sp
                    )
                    Text(
                        "Commissions are processed on the 10th of every month for all completed orders of the previous month.",
                        color = Color(0xFFE0E7FF),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium
                    )
                    Button(
                        onClick = {
                            val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://vrhere.in/terms"))
                            context.startActivity(intent)
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = Color.White.copy(alpha = 0.15f)),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("View Policy", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    }
                }
            }
        }

        // Bank summary details card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        "Bank Details",
                        fontWeight = FontWeight.Black,
                        fontSize = 15.sp,
                        color = Color(0xFF1E293B)
                    )

                    val bank = profile?.bankDetails
                    if (bank != null && bank.accountNumber.isNotEmpty()) {
                        DetailRow("Holder Name", bank.accountName)
                        DetailRow("Bank Name", bank.bankName)
                        DetailRow("Account No.", bank.accountNumber.takeLast(4).let { "•••• $it" })
                        DetailRow("IFSC Code", bank.ifscCode)
                        DetailRow("PAN Details", profile.panCard ?: "Not provided")
                    } else {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(Color(0xFFFFFBEB), RoundedCornerShape(12.dp))
                                .padding(12.dp)
                        ) {
                            Text(
                                "No bank account added yet. Go to Settings tab to add payout details.",
                                color = Color(0xFFB45309),
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Medium
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
}

// --- REFERRALS LIST TAB ---
@Composable
fun PartnerReferralsTab(
    viewModel: PartnerDashboardViewModel,
    searchTerm: String,
    onSearchTermChange: (String) -> Unit
) {
    val orders = viewModel.orders.filter {
        it.clientName.contains(searchTerm, ignoreCase = true) ||
                it.serviceName.contains(searchTerm, ignoreCase = true)
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Search bar & title
        item {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    "Referral List",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF1E293B)
                )
                Text(
                    "Detailed list of all successful business referrals associated with your account.",
                    fontSize = 12.sp,
                    color = Color(0xFF64748B)
                )

                OutlinedTextField(
                    value = searchTerm,
                    onValueChange = onSearchTermChange,
                    placeholder = { Text("Search client or service...") },
                    leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                    shape = RoundedCornerShape(16.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = Color(0xFFF59E0B),
                        unfocusedBorderColor = Color(0xFFE2E8F0),
                        focusedContainerColor = Color.White,
                        unfocusedContainerColor = Color.White,
                        disabledContainerColor = Color.White,
                        errorContainerColor = Color.White
                    ),
                    modifier = Modifier.fillMaxWidth()
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
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Box(
                            modifier = Modifier
                                .size(56.dp)
                                .background(Color(0xFFF1F5F9), CircleShape),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.FolderOpen, contentDescription = null, tint = Color(0xFF94A3B8))
                        }
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            "No referrals found",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = Color(0xFF1E293B)
                        )
                        Text(
                            "Clients who register using your number will appear here.",
                            fontSize = 11.sp,
                            color = Color(0xFF64748B),
                            modifier = Modifier.padding(top = 4.dp)
                        )
                    }
                }
            }
        } else {
            items(orders) { order ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
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

                            // Status Badge
                            Box(
                                modifier = Modifier
                                    .background(
                                        when (order.status) {
                                            "Completed" -> Color(0xFFD1FAE5)
                                            "Pending Documents" -> Color(0xFFFEF3C7)
                                            "Waiting for Clarification" -> Color(0xFFFEE2E2)
                                            else -> Color(0xFFE0E7FF)
                                        },
                                        RoundedCornerShape(8.dp)
                                    )
                                    .padding(horizontal = 8.dp, vertical = 4.dp)
                            ) {
                                Text(
                                    order.status,
                                    color = when (order.status) {
                                        "Completed" -> Color(0xFF065F46)
                                        "Pending Documents" -> Color(0xFF92400E)
                                        "Waiting for Clarification" -> Color(0xFF991B1B)
                                        else -> Color(0xFF3730A3)
                                    },
                                    fontSize = 8.sp,
                                    fontWeight = FontWeight.Black
                                )
                            }
                        }

                        Divider(color = Color(0xFFF1F5F9))

                        Row(
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column {
                                Text(
                                    "ORDER DATE",
                                    fontSize = 8.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF94A3B8)
                                )
                                Text(
                                    formatDate(order.createdAt),
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFF475569)
                                )
                            }

                            Column(horizontalAlignment = Alignment.End) {
                                Text(
                                    "COMMISSION EARNED",
                                    fontSize = 8.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF94A3B8)
                                )
                                Text(
                                    formatINR(order.partnerCommissionAmount),
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF10B981)
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

// --- EARNINGS TAB ---
@Composable
fun PartnerEarningsTab(viewModel: PartnerDashboardViewModel) {
    val orders = viewModel.orders

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Earnings Summary",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF1E293B)
                )
                Text(
                    "Track commission earnings and upcoming settlement details.",
                    fontSize = 12.sp,
                    color = Color(0xFF64748B)
                )
            }
        }

        // Big Wallet card
        item {
            val totalCommission = orders.sumOf { it.partnerCommissionAmount }
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        brush = Brush.linearGradient(listOf(Color(0xFF10B981), Color(0xFF047857))),
                        shape = RoundedCornerShape(24.dp)
                    )
                    .padding(24.dp)
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    Text(
                        "LIFETIME COMMISSION",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFFD1FAE5),
                        letterSpacing = 1.sp
                    )
                    Text(
                        formatINR(totalCommission),
                        fontSize = 32.sp,
                        fontWeight = FontWeight.Black,
                        color = Color.White
                    )
                    Divider(color = Color.White.copy(alpha = 0.2f))
                    Row(
                        horizontalArrangement = Arrangement.SpaceBetween,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column {
                            Text(
                                "PAID OUT",
                                fontSize = 9.sp,
                                color = Color(0xFFD1FAE5),
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                formatINR(orders.filter { it.status == "Completed" }.sumOf { it.partnerCommissionAmount }),
                                color = Color.White,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Black
                            )
                        }
                        Column(horizontalAlignment = Alignment.End) {
                            Text(
                                "PENDING SETTLEMENT",
                                fontSize = 9.sp,
                                color = Color(0xFFD1FAE5),
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                formatINR(orders.filter { it.status != "Completed" }.sumOf { it.partnerCommissionAmount }),
                                color = Color.White,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Black
                            )
                        }
                    }
                }
            }
        }

        // Commission structure explanation card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(modifier = Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Star, contentDescription = null, tint = Color(0xFFF59E0B))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            "Standard Referral Terms",
                            fontWeight = FontWeight.Black,
                            fontSize = 14.sp,
                            color = Color(0xFF1E293B)
                        )
                    }
                    Text(
                        "You earn a flat 10% commission on the service fee of every client order registered with your referral code. The commission amount is credited to your bank account after client payment verification.",
                        fontSize = 11.sp,
                        color = Color(0xFF64748B),
                        lineHeight = 16.sp
                    )
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(60.dp))
        }
    }
}

// --- SETTINGS TAB ---
@Composable
fun PartnerSettingsTab(viewModel: PartnerDashboardViewModel) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Account Settings",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF1E293B)
                )
                Text(
                    "Manage your professional identity and payout preferences.",
                    fontSize = 12.sp,
                    color = Color(0xFF64748B)
                )
            }
        }

        // Professional Identity Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(modifier = Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Person, contentDescription = null, tint = Color(0xFF0F172A))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            "Professional Identity",
                            fontWeight = FontWeight.Black,
                            fontSize = 15.sp,
                            color = Color(0xFF1E293B)
                        )
                    }

                    OutlinedTextField(
                        value = viewModel.nameInput,
                        onValueChange = { viewModel.nameInput = it },
                        label = { Text("Full Name") },
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth()
                    )

                    OutlinedTextField(
                        value = viewModel.panCardInput,
                        onValueChange = { viewModel.panCardInput = it },
                        label = { Text("PAN Card Number") },
                        shape = RoundedCornerShape(14.dp),
                        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters),
                        modifier = Modifier.fillMaxWidth()
                    )

                    // Read-only email and phone
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(Color(0xFFF1F5F9), RoundedCornerShape(14.dp))
                            .padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                            Text("Email ID", fontSize = 10.sp, color = Color(0xFF64748B), fontWeight = FontWeight.Bold)
                            Text(viewModel.profile?.email ?: "", fontSize = 11.sp, color = Color(0xFF334155), fontWeight = FontWeight.Black)
                        }
                        Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                            Text("Referral Code (Phone)", fontSize = 10.sp, color = Color(0xFF64748B), fontWeight = FontWeight.Bold)
                            Text(viewModel.profile?.phone ?: "", fontSize = 11.sp, color = Color(0xFF334155), fontWeight = FontWeight.Black)
                        }
                    }
                }
            }
        }

        // Payout Destination Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(modifier = Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.CreditCard, contentDescription = null, tint = Color(0xFF4F46E5))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            "Payout Destination",
                            fontWeight = FontWeight.Black,
                            fontSize = 15.sp,
                            color = Color(0xFF1E293B)
                        )
                    }

                    OutlinedTextField(
                        value = viewModel.bankAccountNameInput,
                        onValueChange = { viewModel.bankAccountNameInput = it },
                        label = { Text("Account Holder Name") },
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth()
                    )

                    OutlinedTextField(
                        value = viewModel.bankNameInput,
                        onValueChange = { viewModel.bankNameInput = it },
                        label = { Text("Bank Name") },
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth()
                    )

                    OutlinedTextField(
                        value = viewModel.bankAccountNumberInput,
                        onValueChange = { viewModel.bankAccountNumberInput = it },
                        label = { Text("Account Number") },
                        shape = RoundedCornerShape(14.dp),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.fillMaxWidth()
                    )

                    OutlinedTextField(
                        value = viewModel.bankIfscCodeInput,
                        onValueChange = { viewModel.bankIfscCodeInput = it },
                        label = { Text("IFSC Code") },
                        shape = RoundedCornerShape(14.dp),
                        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters),
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        }

        // Submit Button
        item {
            Button(
                onClick = { viewModel.updateProfile() },
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF0F172A)),
                shape = RoundedCornerShape(16.dp),
                enabled = !viewModel.isSavingProfile,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp)
            ) {
                if (viewModel.isSavingProfile) {
                    CircularProgressIndicator(color = Color.White, modifier = Modifier.size(24.dp))
                } else {
                    Text("Save Payout Preference", fontWeight = FontWeight.Black, fontSize = 14.sp)
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(60.dp))
        }
    }
}

// --- UTILS ---
@Composable
fun PartnerStatCard(
    modifier: Modifier = Modifier,
    title: String,
    value: String,
    label: String,
    icon: ImageVector,
    iconBg: Color,
    iconColor: Color
) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Box(
                    modifier = Modifier
                        .size(34.dp)
                        .background(iconBg, RoundedCornerShape(8.dp)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(imageVector = icon, contentDescription = null, tint = iconColor, modifier = Modifier.size(18.dp))
                }
                Text(
                    text = label,
                    fontSize = 8.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF94A3B8)
                )
            }
            Spacer(modifier = Modifier.height(10.dp))
            Text(title, fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFF64748B))
            Text(value, fontSize = 18.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B), modifier = Modifier.padding(top = 2.dp))
        }
    }
}

@Composable
fun DetailRow(label: String, value: String) {
    Row(
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(label, fontSize = 11.sp, color = Color(0xFF64748B), fontWeight = FontWeight.Medium)
        Text(value, fontSize = 11.sp, color = Color(0xFF1E293B), fontWeight = FontWeight.Black)
    }
}

private fun formatINR(amount: Double): String {
    return try {
        val format = NumberFormat.getCurrencyInstance(Locale("en", "IN"))
        format.maximumFractionDigits = 0
        format.format(amount).replace("Rs.", "₹").replace("INR", "₹")
    } catch (e: Exception) {
        "₹${amount.toInt()}"
    }
}

private fun formatDate(dateStr: String): String {
    return try {
        val inputFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.getDefault()).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        val date = inputFormat.parse(dateStr) ?: return dateStr
        val outputFormat = SimpleDateFormat("dd MMM yyyy", Locale.getDefault())
        outputFormat.format(date)
    } catch (e: Exception) {
        dateStr.split("T").firstOrNull() ?: dateStr
    }
}
