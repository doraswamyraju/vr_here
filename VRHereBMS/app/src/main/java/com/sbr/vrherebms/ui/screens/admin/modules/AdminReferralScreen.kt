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

data class ReferralPartner(
    val id: String,
    val name: String,
    val role: String,
    val totalConversions: Int,
    val earnedCommissions: Double,
    var payoutStatus: String // 'Paid', 'Processing', 'Hold'
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminReferralScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current

    var partnersList by remember {
        mutableStateOf(
            listOf(
                ReferralPartner("1", "Ramesh Kumar", "Chartered Accountant (CA)", 12, 4800.0, "Paid"),
                ReferralPartner("2", "Suresh Sharma", "Tax Consultant", 6, 2100.0, "Processing"),
                ReferralPartner("3", "Vikram Varma", "Business Broker", 4, 1500.0, "Hold"),
                ReferralPartner("4", "Kiran Reddy", "Legal Adviser", 2, 0.0, "Paid")
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
                    text = "PARTNERSHIP REFERRAL LEDGER",
                    color = Color(0xFF38BDF8),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.ExtraBold,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Referrals & Commissions",
                    color = Color.White,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Track active referral channels partner, evaluate commission payments, and disburse bank withdrawals.",
                    color = Color(0xFF94A3B8),
                    fontSize = 12.sp,
                    lineHeight = 16.sp
                )
            }
        }

        // 2. Summary stats deck
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    listOf(
                        Triple("Partners", "${partnersList.size} Accounts", Color(0xFF3B82F6)),
                        Triple("Payouts Done", "Rs. 4,800", Color(0xFF10B981))
                    ).forEach { (title, count, color) ->
                        Card(
                            modifier = Modifier.weight(1f),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            border = BorderStroke(1.dp, Color(0xFFEEF2F6)),
                            shape = RoundedCornerShape(16.dp)
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text(title, fontSize = 9.sp, color = Color(0xFF64748B), fontWeight = FontWeight.Black)
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(count, fontSize = 20.sp, color = Color(0xFF1E293B), fontWeight = FontWeight.Black)
                                Spacer(modifier = Modifier.height(4.dp))
                                Text("Active Hub", fontSize = 8.sp, color = color, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }

            item {
                Text("Registered Partners Directory", color = Color(0xFF1E293B), fontWeight = FontWeight.Bold, fontSize = 15.sp)
            }

            items(partnersList) { partner ->
                val statusColor = when (partner.payoutStatus) {
                    "Paid" -> Color(0xFF10B981)
                    "Processing" -> Color(0xFFF59E0B)
                    else -> Color(0xFFEF4444)
                }

                var expandedPayoutMenu by remember { mutableStateOf(false) }

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
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(36.dp)
                                        .background(Color(0xFFEFF6FF), CircleShape),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        text = partner.name.take(1).uppercase(),
                                        fontWeight = FontWeight.Bold,
                                        color = Color(0xFF3B82F6),
                                        fontSize = 16.sp
                                    )
                                }

                                Column {
                                    Text(
                                        text = partner.name,
                                        fontSize = 14.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color(0xFF1E293B)
                                    )
                                    Text(
                                        text = partner.role,
                                        fontSize = 11.sp,
                                        color = Color(0xFF64748B)
                                    )
                                }
                            }

                            Box(
                                modifier = Modifier
                                    .background(statusColor.copy(alpha = 0.1f), RoundedCornerShape(6.dp))
                                    .clickable { expandedPayoutMenu = true }
                                    .padding(horizontal = 8.dp, vertical = 4.dp)
                            ) {
                                Text(
                                    text = partner.payoutStatus.uppercase(),
                                    color = statusColor,
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Black
                                )
                            }

                            DropdownMenu(
                                expanded = expandedPayoutMenu,
                                onDismissRequest = { expandedPayoutMenu = false }
                            ) {
                                listOf("Paid", "Processing", "Hold").forEach { opt ->
                                    DropdownMenuItem(
                                        text = { Text(opt) },
                                        onClick = {
                                            partnersList = partnersList.map { old ->
                                                if (old.id == partner.id) old.copy(payoutStatus = opt) else old
                                            }
                                            Toast.makeText(context, "Payout updated to $opt", Toast.LENGTH_SHORT).show()
                                            expandedPayoutMenu = false
                                        }
                                    )
                                }
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
                            Text(
                                text = "Conversions: ${partner.totalConversions} Projects",
                                fontSize = 11.sp,
                                color = Color(0xFF475569),
                                fontWeight = FontWeight.Bold
                            )

                            Text(
                                text = "Commissions: Rs. %,.0f".format(partner.earnedCommissions),
                                fontSize = 11.sp,
                                color = Color(0xFF10B981),
                                fontWeight = FontWeight.Black
                            )
                        }
                    }
                }
            }
        }
    }
}
