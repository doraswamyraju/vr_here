package com.sbr.vrherebms.ui.screens.admin.modules

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel

data class RecurringRetainer(
    val id: String,
    val clientName: String,
    val serviceName: String,
    val price: Double,
    val billingCycle: String, // 'Monthly', 'Quarterly', 'Annual'
    val nextBillingDate: String,
    var isActive: Boolean
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminRecurringScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current

    var retainersList by remember {
        mutableStateOf(
            listOf(
                RecurringRetainer("1", "Rajugari Ventures", "Monthly GSTR GST Filing Retainer", 1500.0, "Monthly", "2026-06-01", true),
                RecurringRetainer("2", "Blue Cat Solutions", "Annual MCA Statutory Auditing Package", 4500.0, "Annual", "2026-07-31", true),
                RecurringRetainer("3", "Gayatri Enterprises", "Monthly ESI & PF Payroll Remittance", 2500.0, "Monthly", "2026-06-05", true),
                RecurringRetainer("4", "Mark Consultancy", "Quarterly Income Tax Advance Payments", 3500.0, "Quarterly", "2026-09-15", false)
            )
        )
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
                    text = "RECURRING SUBSCRIPTION HUB",
                    color = Color(0xFF38BDF8),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.ExtraBold,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Retainers Ledger",
                    color = Color.White,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Audit recurring service subscriptions, adjust monthly retainers schedules, and toggle active packages.",
                    color = Color(0xFF94A3B8),
                    fontSize = 12.sp,
                    lineHeight = 16.sp
                )
            }
        }

        // 2. Retainers Registry List
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item {
                Text("Active Retainers & Subscriptions", color = Color(0xFF1E293B), fontWeight = FontWeight.Bold, fontSize = 15.sp)
            }

            items(retainersList) { retainer ->
                val statusColor = if (retainer.isActive) Color(0xFF10B981) else Color(0xFFEF4444)

                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFEEF2F6))
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(36.dp)
                                        .background(Color(0xFFEFF6FF), CircleShape),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(Icons.Default.Autorenew, contentDescription = null, tint = Color(0xFF3B82F6), modifier = Modifier.size(18.dp))
                                }

                                Column {
                                    Text(
                                        text = retainer.serviceName,
                                        fontSize = 14.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color(0xFF1E293B),
                                        maxLines = 1
                                    )
                                    Text(
                                        text = "Client: ${retainer.clientName}",
                                        fontSize = 11.sp,
                                        color = Color(0xFF64748B)
                                    )
                                }
                            }

                            Box(
                                modifier = Modifier
                                    .background(statusColor.copy(alpha = 0.1f), RoundedCornerShape(6.dp))
                                    .clickable {
                                        retainersList = retainersList.map { old ->
                                            if (old.id == retainer.id) old.copy(isActive = !old.isActive) else old
                                        }
                                        Toast.makeText(context, "Retainer state toggled!", Toast.LENGTH_SHORT).show()
                                    }
                                    .padding(horizontal = 8.dp, vertical = 4.dp)
                            ) {
                                Text(
                                    text = if (retainer.isActive) "ACTIVE" else "PAUSED",
                                    color = statusColor,
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Black
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(10.dp))
                        Divider(color = Color(0xFFF1F5F9))
                        Spacer(modifier = Modifier.height(10.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Icon(Icons.Default.CalendarToday, contentDescription = null, tint = Color(0xFF64748B), modifier = Modifier.size(12.dp))
                                Text(
                                    text = "Next Billing: ${retainer.nextBillingDate} (${retainer.billingCycle})",
                                    fontSize = 11.sp,
                                    color = Color(0xFF64748B),
                                    fontWeight = FontWeight.Bold
                                )
                            }

                            Text(
                                text = "Rs. %,.0f".format(retainer.price) + " / cyc",
                                fontSize = 13.sp,
                                color = Color(0xFF1E293B),
                                fontWeight = FontWeight.Black
                            )
                        }
                    }
                }
            }
        }
    }
}
