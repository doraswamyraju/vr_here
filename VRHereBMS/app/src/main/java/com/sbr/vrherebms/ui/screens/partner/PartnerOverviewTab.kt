package com.sbr.vrherebms.ui.screens.partner

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.PartnerDashboardViewModel

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
