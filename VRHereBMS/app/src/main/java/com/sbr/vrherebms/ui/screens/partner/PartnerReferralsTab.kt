package com.sbr.vrherebms.ui.screens.partner

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
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.PartnerDashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PartnerReferralsTab(
    viewModel: PartnerDashboardViewModel,
    searchTerm: String,
    onSearchTermChange: (String) -> Unit
) {
    val orders = viewModel.orders.filter {
        it.clientName.contains(searchTerm, ignoreCase = true) ||
                it.serviceName.contains(searchTerm, ignoreCase = true)
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Search bar & title
        item {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    "Referral List",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF1E293B)
                )
                Text(
                    "Detailed list of all successful business referrals associated with your account.",
                    fontSize = 12.sp,
                    color = Color(0xFF64748B)
                )

                OutlinedTextField(
                    value = searchTerm,
                    onValueChange = onSearchTermChange,
                    placeholder = { Text("Search client or service...") },
                    leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                    shape = RoundedCornerShape(16.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = Color(0xFFF59E0B),
                        unfocusedBorderColor = Color(0xFFE2E8F0),
                        focusedContainerColor = Color.White,
                        unfocusedContainerColor = Color.White,
                        disabledContainerColor = Color.White,
                        errorContainerColor = Color.White
                    ),
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }

        if (orders.isEmpty()) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 40.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Box(
                            modifier = Modifier
                                .size(56.dp)
                                .background(Color(0xFFF1F5F9), CircleShape),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.FolderOpen, contentDescription = null, tint = Color(0xFF94A3B8))
                        }
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            "No referrals found",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = Color(0xFF1E293B)
                        )
                        Text(
                            "Clients who register using your number will appear here.",
                            fontSize = 11.sp,
                            color = Color(0xFF64748B),
                            modifier = Modifier.padding(top = 4.dp)
                        )
                    }
                }
            }
        } else {
            items(orders) { order ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Row(
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    order.clientName,
                                    fontWeight = FontWeight.Black,
                                    fontSize = 15.sp,
                                    color = Color(0xFF0F172A)
                                )
                                Text(
                                    order.serviceName,
                                    fontSize = 11.sp,
                                    color = Color(0xFF64748B),
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier.padding(top = 2.dp)
                                )
                            }

                            // Status Badge
                            Box(
                                modifier = Modifier
                                    .background(
                                        when (order.status) {
                                            "Completed" -> Color(0xFFD1FAE5)
                                            "Pending Documents" -> Color(0xFFFEF3C7)
                                            "Waiting for Clarification" -> Color(0xFFFEE2E2)
                                            else -> Color(0xFFE0E7FF)
                                        },
                                        RoundedCornerShape(8.dp)
                                    )
                                    .padding(horizontal = 8.dp, vertical = 4.dp)
                            ) {
                                Text(
                                    order.status,
                                    color = when (order.status) {
                                        "Completed" -> Color(0xFF065F46)
                                        "Pending Documents" -> Color(0xFF92400E)
                                        "Waiting for Clarification" -> Color(0xFF991B1B)
                                        else -> Color(0xFF3730A3)
                                    },
                                    fontSize = 8.sp,
                                    fontWeight = FontWeight.Black
                                )
                            }
                        }

                        Divider(color = Color(0xFFF1F5F9))

                        Row(
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column {
                                Text(
                                    "ORDER DATE",
                                    fontSize = 8.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF94A3B8)
                                )
                                Text(
                                    formatDate(order.createdAt),
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFF475569)
                                )
                            }

                            Column(horizontalAlignment = Alignment.End) {
                                Text(
                                    "COMMISSION EARNED",
                                    fontSize = 8.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF94A3B8)
                                )
                                Text(
                                    formatINR(order.partnerCommissionAmount),
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF10B981)
                                )
                            }
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
