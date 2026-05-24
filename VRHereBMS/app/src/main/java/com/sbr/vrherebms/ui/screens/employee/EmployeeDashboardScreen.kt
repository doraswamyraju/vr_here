package com.sbr.vrherebms.ui.screens.employee

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
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.OrderResponse
import com.sbr.vrherebms.ui.screens.hrms.HrmsEmployeeScreen
import com.sbr.vrherebms.viewmodel.EmployeeDashboardViewModel
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EmployeeDashboardScreen(
    viewModel: EmployeeDashboardViewModel,
    userName: String,
    onLogout: () -> Unit
) {
    var activeTab by remember { mutableStateOf("Overview") }
    var selectedOrderForProcessing by remember { mutableStateOf<OrderResponse?>(null) }
    val context = LocalContext.current

    LaunchedEffect(key1 = true) {
        viewModel.syncDashboardData()
        viewModel.eventFlow.collect { event ->
            if (event is EmployeeDashboardViewModel.UiEvent.ShowToast) {
                Toast.makeText(context, event.message, Toast.LENGTH_SHORT).show()
            }
        }
    }

    val lightSlate = Color(0xFFF8FAFC)

    Scaffold(
        topBar = {
            // Exact replication of React Employee Topbar
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
                    Column {
                        Text(
                            text = "VR Here Employee Panel",
                            color = Color(0xFF64748B),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = when (activeTab) {
                                "Overview" -> "Employee Dashboard"
                                "Queue" -> "Work Queue"
                                "Attendance" -> "Attendance Log"
                                else -> activeTab
                            },
                            color = Color(0xFF0F172A),
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Black
                        )
                    }

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        // Refresh Button (styled like a pill button)
                        Row(
                            modifier = Modifier
                                .border(1.5.dp, Color(0xFFE2E8F0), RoundedCornerShape(10.dp))
                                .background(Color.White, RoundedCornerShape(10.dp))
                                .clickable { viewModel.syncDashboardData() }
                                .padding(horizontal = 10.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.Refresh,
                                contentDescription = "Refresh",
                                tint = Color(0xFF475569),
                                modifier = Modifier.size(14.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(
                                text = "Refresh",
                                color = Color(0xFF475569),
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }

                        // User Initials Avatar with Brush Gradient
                        Box(
                            modifier = Modifier
                                .size(36.dp)
                                .background(
                                    brush = Brush.linearGradient(listOf(Color(0xFF6366F1), Color(0xFF3B82F6))),
                                    shape = CircleShape
                                )
                                .clickable {
                                    Toast.makeText(context, "Signing out...", Toast.LENGTH_SHORT).show()
                                    onLogout()
                                },
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = userName.firstOrNull()?.toString()?.uppercase() ?: "E",
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp
                            )
                        }
                    }
                }
                
                // Add support for showing active timer if attendance session clock is running
                val activeSession = viewModel.attendanceLogs.firstOrNull { it.clockOutAt == null }
                if (activeSession != null) {
                    val clockInDate = remember(activeSession.clockInAt) {
                        try {
                            val format = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
                            format.timeZone = TimeZone.getTimeZone("UTC")
                            format.parse(activeSession.clockInAt)
                        } catch (e: Exception) {
                            Date()
                        }
                    }
                    var elapsedSeconds by remember { mutableStateOf(0L) }
                    LaunchedEffect(clockInDate) {
                        while (true) {
                            elapsedSeconds = (System.currentTimeMillis() - clockInDate.time) / 1000
                            kotlinx.coroutines.delay(1000)
                        }
                    }
                    
                    val hours = elapsedSeconds / 3600
                    val minutes = (elapsedSeconds % 3600) / 60
                    val seconds = elapsedSeconds % 60
                    val elapsedLabel = String.format(Locale.US, "%02d:%02d:%02d", hours, minutes, seconds)
                    
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(Color(0xFFEEF2F6))
                            .padding(horizontal = 16.dp, vertical = 6.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(6.dp)
                                    .background(Color(0xFF10B981), CircleShape)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "Active Shift Session:",
                                color = Color(0xFF475569),
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                        Text(
                            text = elapsedLabel,
                            color = Color(0xFF6366F1),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Black
                        )
                    }
                }
                
                HorizontalDivider(
                    thickness = 1.dp,
                    color = Color(0xFFE2E8F0)
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
                        Triple("Queue", Icons.Default.Work, "Queue"),
                        Triple("Attendance", Icons.Default.AccessTime, "Attendance"),
                        Triple("HRMS", Icons.Default.People, "HRMS")
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
                                tint = if (isSelected) Color(0xFF0EA5E9) else Color(0xFF94A3B8),
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
            AnimatedContent(
                targetState = activeTab,
                transitionSpec = {
                    fadeIn() togetherWith fadeOut()
                },
                label = "EmployeeTabContent"
            ) { targetTab ->
                when (targetTab) {
                    "Overview" -> EmployeeOverviewTab(viewModel, userName, onSelectTab = { activeTab = it })
                    "Queue" -> EmployeeQueueTab(
                        viewModel = viewModel,
                        selectedOrder = selectedOrderForProcessing,
                        onSelectOrder = { selectedOrderForProcessing = it }
                    )
                    "Attendance" -> EmployeeAttendanceTab(viewModel)
                    "HRMS" -> HrmsEmployeeScreen()
                }
            }
        }
    }
}
