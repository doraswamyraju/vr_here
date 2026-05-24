package com.sbr.vrherebms.ui.screens.admin

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.ui.screens.hrms.HrmsAdminScreen
import com.sbr.vrherebms.viewmodel.AuthViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminDashboardScreen(
    authViewModel: AuthViewModel,
    userName: String,
    onLogout: () -> Unit
) {
    val context = LocalContext.current
    var activeTab by remember { mutableStateOf("Dashboard") }

    // Colors matching React Web view exactly
    val primaryRed = Color(0xFFC82323)
    val textDark = Color(0xFF1E293B)
    val textMuted = Color(0xFF64748B)
    val boardBackground = Color(0xFFF1F5F9) // Sleek slate backdrop

    Scaffold(
        topBar = {
            Surface(
                color = Color.White,
                tonalElevation = 2.dp,
                border = BorderStroke(1.dp, Color(0xFFEEF2F6))
            ) {
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
                                Toast.makeText(context, "Menu opened", Toast.LENGTH_SHORT).show()
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
                    Card(
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        modifier = Modifier.size(40.dp)
                    ) {
                        Box(
                            modifier = Modifier.fillMaxSize().clickable {
                                Toast.makeText(context, "Notifications: 2 new alerts", Toast.LENGTH_SHORT).show()
                            },
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.Notifications, contentDescription = "Notifications", tint = textDark, modifier = Modifier.size(20.dp))
                            // Red dot notification badge
                            Box(
                                modifier = Modifier
                                    .align(Alignment.TopEnd)
                                    .padding(6.dp)
                                    .size(8.dp)
                                    .background(primaryRed, CircleShape)
                             )
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
                                Toast.makeText(context, "Data sync successful", Toast.LENGTH_SHORT).show()
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
                            text = "A",
                            color = Color.White,
                            fontWeight = FontWeight.Bold,
                            fontSize = 15.sp
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
                        Toast.makeText(context, "New service order request created.", Toast.LENGTH_SHORT).show()
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
            if (activeTab == "Dashboard") {
                AdminHomeTab(userName = userName)
            } else {
                HrmsAdminScreen()
            }
        }
    }
}
