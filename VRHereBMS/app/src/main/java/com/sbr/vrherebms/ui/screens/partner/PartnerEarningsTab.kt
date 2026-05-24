package com.sbr.vrherebms.ui.screens.partner

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CurrencyRupee
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.PartnerDashboardViewModel

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
