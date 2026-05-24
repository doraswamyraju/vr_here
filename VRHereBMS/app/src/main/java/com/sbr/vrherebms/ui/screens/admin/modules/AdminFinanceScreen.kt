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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminFinanceScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var searchQuery by remember { mutableStateOf("") }
    var selectedStatusFilter by remember { mutableStateOf("All") }

    val statusOptions = listOf("All", "Completed", "Pending")

    // Filter payments
    val filteredPayments = adminViewModel.payments.filter { payment ->
        val matchesSearch = payment.customerName.contains(searchQuery, ignoreCase = true) ||
                payment.serviceName.contains(searchQuery, ignoreCase = true) ||
                payment.paymentId.contains(searchQuery, ignoreCase = true)

        val matchesStatus = if (selectedStatusFilter == "All") true else payment.status.equals(selectedStatusFilter, ignoreCase = true)

        matchesSearch && matchesStatus
    }

    // Mathematical calculations
    val totalRevenue = adminViewModel.payments.filter { it.status.equals("Completed", ignoreCase = true) }.sumOf { it.amount }
    val gstCollected = totalRevenue * 0.18 // 18% GST Simulation
    val pendingPayouts = adminViewModel.payments.filter { it.status.equals("Pending", ignoreCase = true) }.sumOf { it.amount }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF1F5F9))
            .padding(16.dp)
    ) {
        // 1. Finance Metric Blocks Row (Ops View)
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // Card 1: Total Revenue
            Card(
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1B4B))
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("TOTAL REVENUE", fontSize = 8.sp, color = Color(0xFF38BDF8), fontWeight = FontWeight.Bold)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text("Rs. %,.0f".format(totalRevenue), fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color.White)
                }
            }

            // Card 2: GST Collected (18%)
            Card(
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("GST COLLECTED", fontSize = 8.sp, color = Color(0xFF64748B), fontWeight = FontWeight.Bold)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text("Rs. %,.0f".format(gstCollected), fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                }
            }

            // Card 3: Pending
            Card(
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("PENDING LEDGER", fontSize = 8.sp, color = Color(0xFF64748B), fontWeight = FontWeight.Bold)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text("Rs. %,.0f".format(pendingPayouts), fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color(0xFFEA580C))
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 2. Search & Filters
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = { Text("Search transactions...", fontSize = 13.sp) },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = Color(0xFF64748B), modifier = Modifier.size(16.dp)) },
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(10.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = Color(0xFF6366F1),
                    unfocusedBorderColor = Color(0xFFE2E8F0)
                ),
                singleLine = true
            )

            statusOptions.forEach { filter ->
                if (filter != "All") {
                    val isSelected = selectedStatusFilter == filter
                    val bg = if (isSelected) Color(0xFF6366F1) else Color.White
                    val textColor = if (isSelected) Color.White else Color(0xFF64748B)

                    Box(
                        modifier = Modifier
                            .background(bg, RoundedCornerShape(10.dp))
                            .clickable { selectedStatusFilter = if (isSelected) "All" else filter }
                            .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(10.dp))
                            .padding(horizontal = 12.dp, vertical = 10.dp)
                    ) {
                        Text(filter, fontSize = 11.sp, fontWeight = FontWeight.Bold, color = textColor)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 3. Transactions List
        if (filteredPayments.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Default.ReceiptLong,
                        contentDescription = null,
                        tint = Color(0xFF94A3B8),
                        modifier = Modifier.size(64.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text("No billing receipts generated yet.", color = Color(0xFF64748B), fontSize = 14.sp)
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                items(filteredPayments) { payment ->
                    val isCompleted = payment.status.equals("Completed", ignoreCase = true)

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFEEF2F6))
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            // Header Payer & Price
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column {
                                    Text(payment.customerName, fontWeight = FontWeight.Bold, fontSize = 14.sp, color = Color(0xFF1E293B))
                                    Text(payment.serviceName, fontSize = 11.sp, color = Color(0xFF64748B))
                                }
                                Text(
                                    text = "Rs. %,.0f".format(payment.amount),
                                    fontWeight = FontWeight.Black,
                                    fontSize = 15.sp,
                                    color = if (isCompleted) Color(0xFF10B981) else Color(0xFFEA580C)
                                )
                            }

                            Spacer(modifier = Modifier.height(10.dp))
                            Divider(color = Color(0xFFF1F5F9))
                            Spacer(modifier = Modifier.height(10.dp))

                            // Details & Download Invoice
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column {
                                    Text("ID: ${payment.paymentId}", fontSize = 10.sp, color = Color(0xFF94A3B8))
                                    Text("Method: ${payment.method} | Status: ${payment.status}", fontSize = 10.sp, color = Color(0xFF94A3B8))
                                }

                                if (isCompleted) {
                                    Row(
                                        modifier = Modifier
                                            .background(Color(0xFFEFF6FF), RoundedCornerShape(8.dp))
                                            .clickable {
                                                Toast.makeText(context, "Opening PDF Invoice link...", Toast.LENGTH_SHORT).show()
                                            }
                                            .padding(horizontal = 10.dp, vertical = 6.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                                    ) {
                                        Icon(Icons.Default.Download, contentDescription = null, tint = Color(0xFF3B82F6), modifier = Modifier.size(12.dp))
                                        Text("Invoice", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFF3B82F6))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
