package com.sbr.vrherebms.ui.screens.admin

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun AdminHomeTab(
    userName: String
) {
    val context = LocalContext.current
    val primaryRed = Color(0xFFC82323)
    val textDark = Color(0xFF1E293B)
    val textMuted = Color(0xFF64748B)

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // A. Gorgeous Purple "Operations Studio" Command Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.Transparent)
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            brush = Brush.linearGradient(
                                colors = listOf(
                                    Color(0xFF1E1B4B), // Very deep navy-purple
                                    Color(0xFF2E1065), // Indigo violet
                                    Color(0xFF0F172A)  // Deep slate
                                )
                            )
                        )
                        .padding(24.dp)
                ) {
                    Column {
                        Text(
                            text = "ADMIN COMMAND CENTER (V1.1.8 - POWER TOOLS)",
                            color = Color(0xFF38BDF8), // Cyan text
                            fontSize = 10.sp,
                            fontWeight = FontWeight.ExtraBold,
                            letterSpacing = 1.sp
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "Operations Studio",
                            color = Color.White,
                            fontSize = 26.sp,
                            fontWeight = FontWeight.Black
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "Service delivery, consultation conversion, and execution status in one place.",
                            color = Color(0xFF94A3B8),
                            fontSize = 13.sp,
                            lineHeight = 18.sp
                        )

                        Spacer(modifier = Modifier.height(20.dp))

                        // Custom capsules/chips inside the studio
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            // Chip 1
                            Box(
                                modifier = Modifier
                                    .weight(1f)
                                    .background(Color.White.copy(alpha = 0.08f), RoundedCornerShape(12.dp))
                                    .padding(horizontal = 12.dp, vertical = 8.dp)
                            ) {
                                Column {
                                    Text("ACTIVE PIPELINE", color = Color(0xFF38BDF8), fontSize = 8.sp, fontWeight = FontWeight.Bold)
                                    Text("9 Projects", color = Color.White, fontSize = 13.sp, fontWeight = FontWeight.Black)
                                }
                            }

                            // Chip 2
                            Box(
                                modifier = Modifier
                                    .weight(1f)
                                    .background(Color.White.copy(alpha = 0.08f), RoundedCornerShape(12.dp))
                                    .padding(horizontal = 12.dp, vertical = 8.dp)
                            ) {
                                Column {
                                    Text("TOTAL VALUE", color = Color(0xFF38BDF8), fontSize = 8.sp, fontWeight = FontWeight.Bold)
                                    Text("Rs. 22,899", color = Color.White, fontSize = 13.sp, fontWeight = FontWeight.Black)
                                }
                            }
                        }
                    }
                }
            }
        }

        // B. 2x2 Grid of Quick Actions
        item {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                // Row 1
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    QuickActionCard(
                        modifier = Modifier.weight(1f),
                        title = "NEW ORDER",
                        icon = Icons.Default.Add,
                        iconColor = Color.White,
                        iconBg = Color(0xFF10B981), // Emerald
                        onClick = { Toast.makeText(context, "New Order Form Opened", Toast.LENGTH_SHORT).show() }
                    )

                    QuickActionCard(
                        modifier = Modifier.weight(1f),
                        title = "ADD TO-DO",
                        icon = Icons.Default.Check,
                        iconColor = Color.White,
                        iconBg = Color(0xFFF59E0B), // Orange/Amber
                        onClick = { Toast.makeText(context, "Add To-Do Dialog Opened", Toast.LENGTH_SHORT).show() }
                    )
                }

                // Row 2
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    QuickActionCard(
                        modifier = Modifier.weight(1f),
                        title = "FINANCE",
                        icon = Icons.Default.AttachMoney,
                        iconColor = Color.White,
                        iconBg = Color(0xFF6366F1), // Violet/Indigo
                        onClick = { Toast.makeText(context, "Financial reports opened", Toast.LENGTH_SHORT).show() }
                    )

                    QuickActionCard(
                        modifier = Modifier.weight(1f),
                        title = "REFRESH",
                        icon = Icons.Default.Sync,
                        iconColor = Color.White,
                        iconBg = Color(0xFF334155), // Slate
                        onClick = { Toast.makeText(context, "Data sync successful", Toast.LENGTH_SHORT).show() }
                    )
                }
            }
        }

        // C. Stat Metric Cards
        item {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                // Stat 1: Total Orders
                StatRowCard(
                    title = "TOTAL ORDERS",
                    value = "9",
                    icon = Icons.Default.Layers,
                    iconBg = Color(0xFFEFF6FF), // Light blue
                    iconColor = Color(0xFF3B82F6)  // Blue
                )

                // Stat 2: Pending
                StatRowCard(
                    title = "PENDING",
                    value = "9",
                    icon = Icons.Default.AccessTime,
                    iconBg = Color(0xFFFFF7ED), // Light orange
                    iconColor = Color(0xFFEA580C)  // Orange
                )

                // Stat 3: Completed
                StatRowCard(
                    title = "COMPLETED",
                    value = "0",
                    icon = Icons.Default.CheckCircle,
                    iconBg = Color(0xFFECFDF5), // Light green
                    iconColor = Color(0xFF10B981)  // Green
                )
            }
        }

        // Spacer to avoid overlapping with bottom bar
        item {
            Spacer(modifier = Modifier.height(40.dp))
        }
    }
}

@Composable
fun QuickActionCard(
    modifier: Modifier = Modifier,
    title: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    iconBg: Color,
    iconColor: Color,
    onClick: () -> Unit
) {
    Card(
        modifier = modifier
            .height(104.dp)
            .clickable { onClick() },
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFEEF2F6)),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(
            modifier = Modifier.fillMaxSize().padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .background(iconBg, RoundedCornerShape(10.dp)),
                contentAlignment = Alignment.Center
            ) {
                Icon(icon, contentDescription = title, tint = iconColor, modifier = Modifier.size(20.dp))
            }
            Spacer(modifier = Modifier.height(10.dp))
            Text(
                text = title,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = Color(0xFF1E293B),
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
fun StatRowCard(
    title: String,
    value: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    iconBg: Color,
    iconColor: Color
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFEEF2F6)),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column {
                Text(
                    text = title,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.ExtraBold,
                    color = Color(0xFF64748B),
                    letterSpacing = 0.5.sp
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = value,
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF1E293B)
                )
            }

            Box(
                modifier = Modifier
                    .size(44.dp)
                    .background(iconBg, CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Icon(icon, contentDescription = title, tint = iconColor, modifier = Modifier.size(22.dp))
            }
        }
    }
}
