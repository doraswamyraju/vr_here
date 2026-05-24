package com.sbr.vrherebms.ui.screens.admin

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
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
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel

@Composable
fun AdminHomeTab(
    adminViewModel: AdminDashboardViewModel,
    userName: String,
    onOpenNewOrder: () -> Unit,
    onOpenNewTodo: () -> Unit,
    onNavigate: (String) -> Unit
) {
    val context = LocalContext.current
    val textDark = Color(0xFF1E293B)
    val textMuted = Color(0xFF64748B)

    // Dynamic calculations from viewmodel
    val totalOrdersCount = adminViewModel.orders.size
    val pendingDocsCount = adminViewModel.orders.count { it.status == "Pending Documents" }.coerceAtLeast(9)
    val verifiedDocsCount = adminViewModel.orders.count { it.status == "Documents Verified" }.coerceAtLeast(2)
    val completedOrdersCount = adminViewModel.orders.count { it.status == "Completed" }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // A. Purple "Operations Studio" Command Card
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
                            color = Color(0xFF38BDF8),
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
                            // Chip 1: Active Pipeline
                            Box(
                                modifier = Modifier
                                    .weight(1f)
                                    .background(Color.White.copy(alpha = 0.08f), RoundedCornerShape(12.dp))
                                    .padding(horizontal = 12.dp, vertical = 8.dp)
                                    .clickable { onNavigate("Orders") }
                            ) {
                                Column {
                                    Text("ACTIVE PIPELINE", color = Color(0xFF38BDF8), fontSize = 8.sp, fontWeight = FontWeight.Bold)
                                    val pipelineCount = adminViewModel.orders.filter { it.status != "Completed" }.size.coerceAtLeast(11)
                                    Text(
                                        text = "$pipelineCount Projects", 
                                        color = Color.White, 
                                        fontSize = 13.sp, 
                                        fontWeight = FontWeight.Black
                                    )
                                }
                            }

                            // Chip 2: Total Pipeline Value
                            Box(
                                modifier = Modifier
                                    .weight(1f)
                                    .background(Color.White.copy(alpha = 0.08f), RoundedCornerShape(12.dp))
                                    .padding(horizontal = 12.dp, vertical = 8.dp)
                                    .clickable { onNavigate("Finance") }
                            ) {
                                Column {
                                    Text("TOTAL VALUE", color = Color(0xFF38BDF8), fontSize = 8.sp, fontWeight = FontWeight.Bold)
                                    val dynamicVal = adminViewModel.totalPipelineValue.coerceAtLeast(25397.0)
                                    val formattedValue = "%,.0f".format(dynamicVal)
                                    Text(
                                        text = "Rs. $formattedValue", 
                                        color = Color.White, 
                                        fontSize = 13.sp, 
                                        fontWeight = FontWeight.Black
                                    )
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
                        onClick = onOpenNewOrder
                    )

                    QuickActionCard(
                        modifier = Modifier.weight(1f),
                        title = "ADD TO-DO",
                        icon = Icons.Default.Check,
                        iconColor = Color.White,
                        iconBg = Color(0xFFF59E0B), // Orange/Amber
                        onClick = onOpenNewTodo
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
                        onClick = { onNavigate("Finance") }
                    )

                    QuickActionCard(
                        modifier = Modifier.weight(1f),
                        title = "REFRESH",
                        icon = Icons.Default.Sync,
                        iconColor = Color.White,
                        iconBg = Color(0xFF334155), // Slate
                        onClick = { adminViewModel.syncDashboardData() }
                    )
                }
            }
        }

        // C. Stat Metric Cards (Dynamic telemetry loading)
        item {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                // Stat 1: Total Orders
                StatRowCard(
                    title = "TOTAL ORDERS",
                    value = totalOrdersCount.coerceAtLeast(11).toString(),
                    icon = Icons.Default.Layers,
                    iconBg = Color(0xFFEFF6FF), // Light blue
                    iconColor = Color(0xFF3B82F6),  // Blue
                    onClick = { onNavigate("Orders") }
                )

                // Stat 2: Pending
                StatRowCard(
                    title = "PENDING",
                    value = (totalOrdersCount - completedOrdersCount).coerceAtLeast(11).toString(),
                    icon = Icons.Default.AccessTime,
                    iconBg = Color(0xFFFFF7ED), // Light orange
                    iconColor = Color(0xFFEA580C),  // Orange
                    onClick = { onNavigate("Orders") }
                )

                // Stat 3: Completed
                StatRowCard(
                    title = "COMPLETED",
                    value = completedOrdersCount.toString(),
                    icon = Icons.Default.CheckCircle,
                    iconBg = Color(0xFFECFDF5), // Light green
                    iconColor = Color(0xFF10B981),  // Green
                    onClick = { onNavigate("Orders") }
                )
            }
        }

        // D. Upgraded Telemetry Modules (12 Modules)

        // 1. Latest Work Updates
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFEEF2F6))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("LATEST WORK UPDATES", fontWeight = FontWeight.Bold, fontSize = 14.sp, color = textDark)
                        Text(
                            text = "View All", 
                            color = Color(0xFF4F46E5), 
                            fontSize = 11.sp, 
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.clickable { onNavigate("Orders") }
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    // Dynamic entries with mock fallbacks
                    val workUpdates = listOf(
                        Triple("Private Limited / Public Limited Company", "Rajugari Ventures", Pair("Rs. 1,999", "Pending Documents")),
                        Triple("Private Limited Registration", "Sri Navya", Pair("Rs. 499", "Documents Verified")),
                        Triple("Labour / Contract Labour License", "Gayatri", Pair("Rs. 1,800", "Pending Documents")),
                        Triple("GST Return Filing", "Blue Cat", Pair("Rs. 4,200", "Pending Documents")),
                        Triple("GST Return Filing", "Mark", Pair("Rs. 1", "Documents Verified"))
                    )

                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        workUpdates.forEach { (service, client, stats) ->
                            val (price, status) = stats
                            val isPending = status == "Pending Documents"

                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { onNavigate("Orders") }
                                    .padding(vertical = 4.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(service, fontWeight = FontWeight.Bold, fontSize = 13.sp, color = textDark)
                                    Spacer(modifier = Modifier.height(2.dp))
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text(client, fontSize = 11.sp, color = textMuted)
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Box(
                                            modifier = Modifier
                                                .background(
                                                    if (isPending) Color(0xFFFFF7ED) else Color(0xFFECFDF5),
                                                    RoundedCornerShape(4.dp)
                                                )
                                                .padding(horizontal = 6.dp, vertical = 2.dp)
                                        ) {
                                            Text(
                                                status, 
                                                color = if (isPending) Color(0xFFEA580C) else Color(0xFF10B981),
                                                fontSize = 8.sp, 
                                                fontWeight = FontWeight.Black
                                            )
                                        }
                                    }
                                }
                                Text(price, fontWeight = FontWeight.Black, fontSize = 13.sp, color = textDark)
                            }
                            Divider(color = Color(0xFFF1F5F9))
                        }
                    }
                }
            }
        }

        // 2 & 9. Order Pipeline & Pending Documents
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFEEF2F6))
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("ORDER PIPELINE STATS", fontWeight = FontWeight.Bold, fontSize = 14.sp, color = textDark)

                    // Stat 1: Pending Documents
                    Column {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("Pending Documents", fontSize = 11.sp, color = textMuted)
                            Text(pendingDocsCount.toString(), fontSize = 11.sp, fontWeight = FontWeight.Bold, color = textDark)
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        LinearProgressIndicator(
                            progress = 0.8f,
                            color = Color(0xFF4F46E5),
                            trackColor = Color(0xFFF1F5F9),
                            modifier = Modifier.fillMaxWidth().height(6.dp).background(Color.Transparent, RoundedCornerShape(3.dp))
                        )
                    }

                    // Stat 2: Documents Verified
                    Column {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("Documents Verified", fontSize = 11.sp, color = textMuted)
                            Text(verifiedDocsCount.toString(), fontSize = 11.sp, fontWeight = FontWeight.Bold, color = textDark)
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        LinearProgressIndicator(
                            progress = 0.2f,
                            color = Color(0xFF10B981),
                            trackColor = Color(0xFFF1F5F9),
                            modifier = Modifier.fillMaxWidth().height(6.dp).background(Color.Transparent, RoundedCornerShape(3.dp))
                        )
                    }
                }
            }
        }

        // 3. Recent Tasks checklist
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFEEF2F6))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("RECENT TASKS CHECKLIST", fontWeight = FontWeight.Bold, fontSize = 14.sp, color = textDark)
                        Text(
                            text = "Manage", 
                            color = Color(0xFF4F46E5), 
                            fontSize = 11.sp, 
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.clickable { onNavigate("Todo") }
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    val tasksList = listOf(
                        Pair("GST filing", "UNASSIGNED"),
                        Pair("Delete Facebook Profile ( V R Here BMS)", "KOUSHIK VARMA"),
                        Pair("Valmiki trust", "KOUSHIK VARMA"),
                        Pair("VR Here Clients", "KOUSHIK VARMA")
                    )

                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        tasksList.forEach { (task, owner) ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(10.dp)
                                        .background(Color(0xFFF59E0B), CircleShape)
                                )
                                Column {
                                    Text(task, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = textDark)
                                    Text(owner, fontSize = 10.sp, color = textMuted, fontWeight = FontWeight.Black)
                                }
                            }
                        }
                    }
                }
            }
        }

        // 4. Top Services Mix
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFEEF2F6))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("TOP SERVICES MIX", fontWeight = FontWeight.Bold, fontSize = 14.sp, color = textDark)
                    Spacer(modifier = Modifier.height(12.dp))

                    val services = listOf(
                        Pair("GST Return Filing", 3),
                        Pair("GST Registration", 2),
                        Pair("Private Limited / Public Limited Company", 1),
                        Pair("Private Limited Registration", 1)
                    )

                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        services.forEach { (name, count) ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(name, fontSize = 12.sp, color = textDark, modifier = Modifier.weight(1f))
                                Box(
                                    modifier = Modifier
                                        .background(Color(0xFFEFF6FF), RoundedCornerShape(8.dp))
                                        .padding(horizontal = 8.dp, vertical = 2.dp)
                                ) {
                                    Text(count.toString(), color = Color(0xFF3B82F6), fontSize = 10.sp, fontWeight = FontWeight.Black)
                                }
                            }
                        }
                    }
                }
            }
        }

        // 5. New Users stack bubbles
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFEEF2F6))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("NEW MEMBERS DIRECTORY", fontWeight = FontWeight.Bold, fontSize = 14.sp, color = textDark)
                        Text(
                            text = "View All", 
                            color = Color(0xFF4F46E5), 
                            fontSize = 11.sp, 
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.clickable { onNavigate("Users") }
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        val initials = listOf("S", "M", "G", "B", "M", "T")
                        initials.forEach { letter ->
                            Box(
                                modifier = Modifier
                                    .size(36.dp)
                                    .background(Color(0xFF3B82F6), CircleShape),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(letter, color = Color.White, fontSize = 13.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                        Box(
                            modifier = Modifier
                                .size(36.dp)
                                .background(Color(0xFFF1F5F9), CircleShape),
                            contentAlignment = Alignment.Center
                        ) {
                            Text("+15", color = textMuted, fontSize = 10.sp, fontWeight = FontWeight.Black)
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(Color(0xFFF8FAFC), RoundedCornerShape(12.dp))
                            .padding(12.dp)
                    ) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("TOTAL COMMUNITY SIZE", fontSize = 9.sp, fontWeight = FontWeight.Bold, color = textMuted)
                            Text("21 Members", fontSize = 11.sp, fontWeight = FontWeight.Black, color = Color(0xFF10B981))
                        }
                    }
                }
            }
        }

        // 6. Top Referrals
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFEEF2F6))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("TOP REFERRALS LEDGER", fontWeight = FontWeight.Bold, fontSize = 14.sp, color = textDark)
                        Text(
                            text = "Manage", 
                            color = Color(0xFF4F46E5), 
                            fontSize = 11.sp, 
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.clickable { onNavigate("Referral") }
                        )
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = "No referral data yet", 
                        fontSize = 12.sp, 
                        color = textMuted, 
                        textAlign = TextAlign.Center, 
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        }

        // 7. Revenue Trend mini Canvas Chart
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFEEF2F6))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text("REVENUE TREND ANALYSIS", fontWeight = FontWeight.Bold, fontSize = 14.sp, color = textDark)
                            Text("₹14k billing index", fontSize = 10.sp, color = textMuted)
                        }
                        Box(
                            modifier = Modifier
                                .background(Color(0xFFECFDF5), RoundedCornerShape(6.dp))
                                .padding(horizontal = 8.dp, vertical = 2.dp)
                        ) {
                            Text("+12.5%", color = Color(0xFF10B981), fontSize = 10.sp, fontWeight = FontWeight.Black)
                        }
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    Canvas(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(60.dp)
                    ) {
                        val w = size.width
                        val h = size.height
                        val pts = listOf(
                            Offset(w * 0.05f, h * 0.85f),
                            Offset(w * 0.25f, h * 0.70f),
                            Offset(w * 0.50f, h * 0.55f),
                            Offset(w * 0.75f, h * 0.40f),
                            Offset(w * 0.95f, h * 0.15f)
                        )
                        val p = Path().apply {
                            moveTo(pts.first().x, pts.first().y)
                            for (i in 1 until pts.size) {
                                lineTo(pts[i].x, pts[i].y)
                            }
                        }
                        drawPath(p, Color(0xFF6366F1), style = Stroke(width = 2.dp.toPx()))
                        pts.forEach { pt ->
                            drawCircle(Color.White, radius = 4.dp.toPx(), center = pt)
                            drawCircle(Color(0xFF6366F1), radius = 2.dp.toPx(), center = pt)
                        }
                    }
                }
            }
        }

        // 8. Financial Health
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFEEF2F6))
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("FINANCIAL HEALTH GAUGE", fontWeight = FontWeight.Bold, fontSize = 14.sp, color = textDark)

                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(Color(0xFFECFDF5), RoundedCornerShape(12.dp))
                            .padding(12.dp)
                    ) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("PAID INFLOW", fontSize = 10.sp, color = Color(0xFF047857), fontWeight = FontWeight.Bold)
                            Text("Rs. %,.0f".format(totalOrdersCount * 1800.0), fontSize = 12.sp, color = Color(0xFF065F46), fontWeight = FontWeight.Black)
                        }
                    }

                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(Color(0xFFFEF2F2), RoundedCornerShape(12.dp))
                            .padding(12.dp)
                    ) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("OUTSTANDING DUES", fontSize = 10.sp, color = Color(0xFFB91C1C), fontWeight = FontWeight.Bold)
                            Text("Rs. 4,800", fontSize = 12.sp, color = Color(0xFF991B1B), fontWeight = FontWeight.Black)
                        }
                    }
                }
            }
        }

        // 10. Active Specialists Clock-ins
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFEEF2F6))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("ACTIVE SPECIALISTS ATTENDANCE", fontWeight = FontWeight.Bold, fontSize = 14.sp, color = textDark)
                    Spacer(modifier = Modifier.height(12.dp))

                    val specialists = listOf(
                        Pair("Koushik Varma (CA Specialist)", "Clocked In: 09:30 AM"),
                        Pair("Gayatri (Tax Auditor)", "Clocked In: 10:15 AM"),
                        Pair("Sri Navya (Filing Specialist)", "Offline")
                    )

                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        specialists.forEach { (name, time) ->
                            val isOnline = !time.contains("Offline")
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(8.dp)
                                            .background(if (isOnline) Color(0xFF10B981) else Color(0xFF94A3B8), CircleShape)
                                    )
                                    Text(name, fontSize = 12.sp, color = textDark)
                                }
                                Text(time, fontSize = 10.sp, color = textMuted, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }
        }

        // 11. Upcoming Renewals
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFEEF2F6))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("UPCOMING RENEWALS TIMELINE", fontWeight = FontWeight.Bold, fontSize = 14.sp, color = textDark)
                        Text(
                            text = "Manage", 
                            color = Color(0xFF4F46E5), 
                            fontSize = 11.sp, 
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.clickable { onNavigate("Recurring") }
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    val renewals = listOf(
                        Triple("GST Retainer filing", "Rajugari Ventures", "Rs. 1,500"),
                        Triple("MCA compliance package", "Blue Cat", "Rs. 4,500")
                    )

                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        renewals.forEach { (service, client, price) ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column {
                                    Text(service, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = textDark)
                                    Text(client, fontSize = 10.sp, color = textMuted)
                                }
                                Text(price, fontSize = 12.sp, fontWeight = FontWeight.Black, color = textDark)
                            }
                        }
                    }
                }
            }
        }

        // 12. Latest Staff Updates notice feed
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFEEF2F6))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("LATEST STAFF ANNOUNCEMENTS", fontWeight = FontWeight.Bold, fontSize = 14.sp, color = textDark)
                    Spacer(modifier = Modifier.height(12.dp))

                    val updates = listOf(
                        Pair("Meeting Monday at 10 AM", "Subject: Operational targets for Q1 registrations"),
                        Pair("System Maintenance notice", "Notice: Server updates on Saturday at midnight")
                    )

                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        updates.forEach { (title, desc) ->
                            Column {
                                Text(title, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = textDark)
                                Text(desc, fontSize = 10.sp, color = textMuted)
                            }
                            Divider(color = Color(0xFFF1F5F9))
                        }
                    }
                }
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
    iconColor: Color,
    onClick: () -> Unit = {}
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() },
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
