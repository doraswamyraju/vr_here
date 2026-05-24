package com.sbr.vrherebms.ui.screens.partner

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.animation.*
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.PartnerDashboardViewModel
import com.sbr.vrherebms.viewmodel.PartnerDashboardState

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
