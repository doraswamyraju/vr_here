package com.sbr.vrherebms.ui.screens.admin.modules

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.animation.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.sbr.vrherebms.data.model.OrderResponse
import com.sbr.vrherebms.data.model.UserResponse
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel
import java.text.NumberFormat
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminCustomersScreen(
    adminViewModel: AdminDashboardViewModel,
    onViewOrder: ((String) -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val indianFormat = remember { NumberFormat.getCurrencyInstance(Locale("en", "IN")) }
    var searchQuery by remember { mutableStateOf("") }
    var selectedCustomerForModal by remember { mutableStateOf<UserResponse?>(null) }

    // 1. Filter users with client role
    val customers = remember(adminViewModel.users) {
        adminViewModel.users.filter { it.role.equals("client", ignoreCase = true) }
    }

    val customerAnalytics = remember(customers, adminViewModel.orders) {
        customers.associate { c ->
            val clientOrders = adminViewModel.orders.filter { o ->
                (o.email.equals(c.email, ignoreCase = true)) ||
                (c.phone != null && o.phone == c.phone)
            }
            val totalRevenue = clientOrders.sumOf { it.price }
            val activeCount = clientOrders.count { !it.status.equals("Completed", ignoreCase = true) }
            val outstandingBalance = 0.0

            c.idVal to Triple<Double, Int, Double>(totalRevenue, activeCount, outstandingBalance)
        }
    }

    // Filter customers by search
    val filteredCustomers = remember(customers, searchQuery) {
        if (searchQuery.isBlank()) customers
        else {
            val q = searchQuery.trim().lowercase()
            customers.filter {
                it.name.lowercase().contains(q) ||
                it.email.lowercase().contains(q) ||
                (it.phone != null && it.phone.contains(q)) ||
                (it.companyName != null && it.companyName.lowercase().contains(q))
            }
        }
    }

    val totalClientRevenue = remember(customerAnalytics) { customerAnalytics.values.sumOf { it.first } }
    val totalActiveOrders = remember(customerAnalytics) { customerAnalytics.values.sumOf { it.second } }
    val totalOutstanding = remember(customerAnalytics) { customerAnalytics.values.sumOf { it.third } }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF8FAFC))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Top Command Header
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A))
        ) {
            Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    text = "CUSTOMER DIRECTORY & CRM",
                    color = Color(0xFF38BDF8),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Black,
                    letterSpacing = 1.sp
                )
                Text(
                    text = "Customers Hub",
                    color = Color.White,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Black
                )
                Text(
                    text = "Active registered enterprise clients, lifetime revenue metrics, active workflow pipeline, and billing ledger.",
                    color = Color(0xFF94A3B8),
                    fontSize = 11.sp,
                    lineHeight = 16.sp
                )
            }
        }

        // Metrics Summary Row
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Card(
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("Total Clients", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B))
                    Spacer(modifier = Modifier.height(2.dp))
                    Text("${customers.size}", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                }
            }

            Card(
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("Total Revenue", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B))
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(indianFormat.format(totalClientRevenue), fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color(0xFF059669))
                }
            }

            Card(
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("Active Orders", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B))
                    Spacer(modifier = Modifier.height(2.dp))
                    Text("$totalActiveOrders", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFF4F46E5))
                }
            }
        }

        // Search Bar
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            placeholder = { Text("Search client by name, email, phone...", fontSize = 12.sp) },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(16.dp)) },
            singleLine = true
        )

        // Customer List
        if (filteredCustomers.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = if (customers.isEmpty()) "No registered customers found." else "No customers match '$searchQuery'.",
                    color = Color(0xFF94A3B8),
                    fontSize = 13.sp
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                contentPadding = PaddingValues(bottom = 90.dp)
            ) {
                items(filteredCustomers) { cust ->
                    val analytics = customerAnalytics[cust.idVal] ?: Triple(0.0, 0, 0.0)
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { selectedCustomerForModal = cust },
                        shape = RoundedCornerShape(18.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(42.dp)
                                            .background(Color(0xFFEEF2FF), CircleShape),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Text(
                                            text = cust.name.take(1).uppercase(),
                                            fontSize = 16.sp,
                                            fontWeight = FontWeight.Black,
                                            color = Color(0xFF4F46E5)
                                        )
                                    }
                                    Column {
                                        Text(
                                            text = cust.name,
                                            fontWeight = FontWeight.Black,
                                            fontSize = 14.sp,
                                            color = Color(0xFF0F172A),
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                        cust.companyName?.let { comp ->
                                            Text(
                                                text = comp,
                                                fontSize = 11.sp,
                                                color = Color(0xFF64748B),
                                                fontWeight = FontWeight.SemiBold
                                            )
                                        }
                                        Text(
                                            text = cust.email,
                                            fontSize = 11.sp,
                                            color = Color(0xFF94A3B8)
                                        )
                                    }
                                }

                                Button(
                                    onClick = { selectedCustomerForModal = cust },
                                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF1F5F9)),
                                    shape = RoundedCornerShape(10.dp),
                                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                                ) {
                                    Text("View Profile", color = Color(0xFF1E293B), fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                }
                            }

                            Divider(color = Color(0xFFF1F5F9))

                            // Bottom Metrics Row
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Column {
                                    Text("Total Spend", fontSize = 9.sp, color = Color(0xFF94A3B8))
                                    Text(
                                        indianFormat.format(analytics.first),
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Black,
                                        color = Color(0xFF059669)
                                    )
                                }
                                Column {
                                    Text("Active Orders", fontSize = 9.sp, color = Color(0xFF94A3B8))
                                    Text(
                                        "${analytics.second} active",
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Black,
                                        color = Color(0xFF4F46E5)
                                    )
                                }
                                Column(horizontalAlignment = Alignment.End) {
                                    Text("Contact", fontSize = 9.sp, color = Color(0xFF94A3B8))
                                    Text(
                                        cust.phone ?: "Not Provided",
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.SemiBold,
                                        color = Color(0xFF0F172A)
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Customer Detailed Modal Dialog
    if (selectedCustomerForModal != null) {
        val cust = selectedCustomerForModal!!
        val custOrders = adminViewModel.orders.filter { o ->
            (o.email.equals(cust.email, ignoreCase = true)) ||
            (cust.phone != null && o.phone == cust.phone)
        }
        val totalRevenue = custOrders.sumOf { it.price }

        Dialog(onDismissRequest = { selectedCustomerForModal = null }) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(8.dp),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(
                    modifier = Modifier
                        .padding(20.dp)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Customer Profile",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Black,
                            color = Color(0xFF0F172A)
                        )
                        IconButton(onClick = { selectedCustomerForModal = null }) {
                            Icon(Icons.Default.Close, contentDescription = "Close", tint = Color(0xFF64748B))
                        }
                    }

                    // Profile Summary Card
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFF8FAFC)),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text(text = cust.name, fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                            cust.companyName?.let { Text(text = it, fontSize = 12.sp, color = Color(0xFF4F46E5), fontWeight = FontWeight.Bold) }
                            Text(text = "Email: ${cust.email}", fontSize = 11.sp, color = Color(0xFF475569))
                            Text(text = "Phone: ${cust.phone ?: "N/A"}", fontSize = 11.sp, color = Color(0xFF475569))
                            cust.gstin?.let { Text(text = "GSTIN: $it", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF059669)) }
                            Divider(modifier = Modifier.padding(vertical = 4.dp), color = Color(0xFFE2E8F0))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text("Lifetime Spend:", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF334155))
                                Text(indianFormat.format(totalRevenue), fontSize = 12.sp, fontWeight = FontWeight.Black, color = Color(0xFF059669))
                            }
                        }
                    }

                    // Order History Section
                    Text("Associated Orders & Services (${custOrders.size})", fontWeight = FontWeight.Black, fontSize = 13.sp, color = Color(0xFF0F172A))

                    if (custOrders.isEmpty()) {
                        Text("No orders created yet for this client.", fontSize = 11.sp, color = Color(0xFF94A3B8))
                    } else {
                        custOrders.forEach { order ->
                            Card(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        selectedCustomerForModal = null
                                        adminViewModel.selectedOrderId = order.id
                                    },
                                shape = RoundedCornerShape(12.dp),
                                colors = CardDefaults.cardColors(containerColor = Color.White),
                                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                            ) {
                                Row(
                                    modifier = Modifier.padding(12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(text = order.serviceName, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                        order.packageName?.let { Text(text = it, fontSize = 10.sp, color = Color(0xFF64748B)) }
                                        Text(text = "Status: ${order.status}", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFF4F46E5))
                                    }
                                    Column(horizontalAlignment = Alignment.End) {
                                        Text(
                                            text = indianFormat.format(order.price ?: 0.0),
                                            fontSize = 12.sp,
                                            fontWeight = FontWeight.Black,
                                            color = Color(0xFF0F172A)
                                        )
                                        Text("Tap to view", fontSize = 9.sp, color = Color(0xFF4F46E5))
                                    }
                                }
                            }
                        }
                    }

                    // Action buttons
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        cust.phone?.let { p ->
                            Button(
                                onClick = {
                                    val intent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:$p"))
                                    context.startActivity(intent)
                                },
                                modifier = Modifier.weight(1f),
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF059669)),
                                shape = RoundedCornerShape(12.dp)
                            ) {
                                Icon(Icons.Default.Phone, contentDescription = null, modifier = Modifier.size(14.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Call", fontWeight = FontWeight.Bold)
                            }
                        }
                        Button(
                            onClick = {
                                val intent = Intent(Intent.ACTION_SENDTO, Uri.parse("mailto:${cust.email}"))
                                context.startActivity(intent)
                            },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Icon(Icons.Default.Email, contentDescription = null, modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Email", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }
    }
}
