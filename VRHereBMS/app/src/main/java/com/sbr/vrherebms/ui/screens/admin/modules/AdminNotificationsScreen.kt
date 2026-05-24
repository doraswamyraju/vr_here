package com.sbr.vrherebms.ui.screens.admin.modules

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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.NotificationResponse
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminNotificationsScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var announcementTitle by remember { mutableStateOf("") }
    var announcementMsg by remember { mutableStateOf("") }
    var announcementClass by remember { mutableStateOf("System") }

    val notificationClasses = listOf("All", "Order", "Payment", "Ticket", "System")
    var selectedClassFilter by remember { mutableStateOf("All") }

    val filteredNotifications = remember(selectedClassFilter, adminViewModel.notifications) {
        adminViewModel.notifications.filter {
            selectedClassFilter == "All" || it.type.equals(selectedClassFilter, ignoreCase = true)
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF1F5F9))
    ) {
        // 1. Sleek Command Header
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1B4B))
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Text(
                    text = "NOTIFICATION & FEEDS CENTER",
                    color = Color(0xFF38BDF8),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.ExtraBold,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Broadcast & Alerts",
                    color = Color.White,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Dispatch broad notices to specialists staff portals, review system orders alerts, and clear unread ledgers.",
                    color = Color(0xFF94A3B8),
                    fontSize = 12.sp,
                    lineHeight = 16.sp
                )
            }
        }

        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Section 1: Dispatch Bulletin Announcements Form
            item {
                Text("Broadcast Announcements Bulletin", color = Color(0xFF1E293B), fontWeight = FontWeight.Bold, fontSize = 15.sp)
            }

            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFEEF2F6))
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        OutlinedTextField(
                            value = announcementTitle,
                            onValueChange = { announcementTitle = it },
                            label = { Text("Bulletin Subject Title") },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp)
                        )

                        OutlinedTextField(
                            value = announcementMsg,
                            onValueChange = { announcementMsg = it },
                            label = { Text("Detailed Alert Message") },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            minLines = 2
                        )

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                listOf("System", "Alert").forEach { cls ->
                                    val isSel = announcementClass == cls
                                    Box(
                                        modifier = Modifier
                                            .background(
                                                if (isSel) Color(0xFFEFF6FF) else Color.Transparent,
                                                RoundedCornerShape(8.dp)
                                            )
                                            .clickable { announcementClass = cls }
                                            .border(
                                                1.dp,
                                                if (isSel) Color(0xFF3B82F6) else Color(0xFFE2E8F0),
                                                RoundedCornerShape(8.dp)
                                            )
                                            .padding(horizontal = 12.dp, vertical = 6.dp)
                                    ) {
                                        Text(
                                            cls,
                                            fontSize = 11.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = if (isSel) Color(0xFF3B82F6) else Color(0xFF64748B)
                                        )
                                    }
                                }
                            }

                            Button(
                                onClick = {
                                    if (announcementTitle.isBlank() || announcementMsg.isBlank()) {
                                        Toast.makeText(context, "Please fill subject and message details", Toast.LENGTH_SHORT).show()
                                        return@Button
                                    }
                                    Toast.makeText(context, "System announcement broadcasted to all specialists!", Toast.LENGTH_SHORT).show()
                                    announcementTitle = ""
                                    announcementMsg = ""
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier.height(40.dp)
                            ) {
                                Icon(Icons.Default.Send, contentDescription = null, modifier = Modifier.size(14.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Broadcast Alert", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }

            // Section 2: Review Alerts Ledger
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("System Alerts Ledger", color = Color(0xFF1E293B), fontWeight = FontWeight.Bold, fontSize = 15.sp)
                    Text(
                        text = "Mark all read",
                        color = Color(0xFF4F46E5),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Black,
                        modifier = Modifier.clickable {
                            adminViewModel.notifications.forEach { notif ->
                                adminViewModel.markNotificationAsRead(notif.id)
                            }
                            Toast.makeText(context, "All marked as read!", Toast.LENGTH_SHORT).show()
                        }
                    )
                }
            }

            // Filter Chips
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    notificationClasses.forEach { cls ->
                        val isSelected = selectedClassFilter == cls
                        Box(
                            modifier = Modifier
                                .background(
                                    if (isSelected) Color(0xFF3B82F6) else Color.White,
                                    RoundedCornerShape(12.dp)
                                )
                                .clickable { selectedClassFilter = cls }
                                .border(
                                    1.dp,
                                    if (isSelected) Color.Transparent else Color(0xFFE2E8F0),
                                    RoundedCornerShape(12.dp)
                                )
                                .padding(horizontal = 12.dp, vertical = 6.dp)
                        ) {
                            Text(
                                text = cls,
                                color = if (isSelected) Color.White else Color(0xFF64748B),
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
            }

            // Notifications List
            if (filteredNotifications.isEmpty()) {
                item {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 40.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            "All caught up! No active alert feeds found under $selectedClassFilter.",
                            color = Color(0xFF64748B),
                            fontSize = 12.sp,
                            textAlign = TextAlign.Center
                        )
                    }
                }
            } else {
                items(filteredNotifications) { notif ->
                    val isRead = notif.isRead
                    val border = if (isRead) BorderStroke(1.dp, Color(0xFFEEF2F6)) else BorderStroke(1.dp, Color(0xFFFECACA))
                    val bg = if (isRead) Color.White else Color(0xFFFFF5F5)

                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                adminViewModel.markNotificationAsRead(notif.id)
                            },
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = bg),
                        border = border
                    ) {
                        Row(
                            modifier = Modifier.padding(16.dp),
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(36.dp)
                                    .background(
                                        if (isRead) Color(0xFFF1F5F9) else Color(0xFFFEE2E2),
                                        CircleShape
                                    ),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Notifications,
                                    contentDescription = null,
                                    tint = if (isRead) Color(0xFF64748B) else Color(0xFFEF4444),
                                    modifier = Modifier.size(18.dp)
                                )
                            }

                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = notif.title,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFF1E293B),
                                    fontSize = 13.sp
                                )
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    text = notif.message,
                                    color = Color(0xFF64748B),
                                    fontSize = 11.sp,
                                    lineHeight = 16.sp
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
