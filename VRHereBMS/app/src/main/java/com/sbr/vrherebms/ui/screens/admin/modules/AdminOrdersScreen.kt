package com.sbr.vrherebms.ui.screens.admin.modules

import android.widget.Toast
import androidx.compose.animation.*
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
import androidx.compose.ui.window.Dialog
import com.sbr.vrherebms.data.model.OrderResponse
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminOrdersScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var searchQuery by remember { mutableStateOf("") }
    var selectedStatusTab by remember { mutableStateOf("All") }
    var selectedOrderForVault by remember { mutableStateOf<OrderResponse?>(null) }

    val statusTabs = listOf("All", "Pending", "Completed")

    // Filter orders dynamically based on search query and status tabs
    val filteredOrders = adminViewModel.orders.filter { order ->
        val matchesSearch = order.clientName.contains(searchQuery, ignoreCase = true) ||
                order.serviceName.contains(searchQuery, ignoreCase = true) ||
                order.id.contains(searchQuery, ignoreCase = true)

        val matchesTab = when (selectedStatusTab) {
            "Pending" -> order.status != "Completed"
            "Completed" -> order.status == "Completed"
            else -> true
        }

        matchesSearch && matchesTab
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF1F5F9))
            .padding(16.dp)
    ) {
        // 1. Search Query Bar
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            placeholder = { Text("Search by Client, Service, or ID...", fontSize = 14.sp) },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = "Search", tint = Color(0xFF64748B)) },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Color(0xFF4F46E5),
                unfocusedBorderColor = Color(0xFFE2E8F0)
            ),
            singleLine = true
        )

        Spacer(modifier = Modifier.height(12.dp))

        // 2. Status Chips Tabs Row
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            statusTabs.forEach { tab ->
                val isSelected = selectedStatusTab == tab
                val bg = if (isSelected) Color(0xFF4F46E5) else Color.White
                val textColor = if (isSelected) Color.White else Color(0xFF64748B)
                val border = if (isSelected) Color.Transparent else Color(0xFFE2E8F0)

                Box(
                    modifier = Modifier
                        .background(bg, RoundedCornerShape(20.dp))
                        .clickable { selectedStatusTab = tab }
                        .border(1.dp, border, RoundedCornerShape(20.dp))
                        .padding(horizontal = 16.dp, vertical = 8.dp)
                ) {
                    Text(
                        text = tab,
                        color = textColor,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 3. Dynamic Projects List
        if (filteredOrders.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Default.LayersClear,
                        contentDescription = null,
                        tint = Color(0xFF94A3B8),
                        modifier = Modifier.size(64.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text("No projects found matching filters.", color = Color(0xFF64748B), fontSize = 14.sp)
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                items(filteredOrders) { order ->
                    var isExpanded by remember { mutableStateOf(false) }

                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { isExpanded = !isExpanded },
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFEEF2F6)),
                        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            // Header: Service Name and Status Badge
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = order.serviceName,
                                    fontSize = 15.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF1E293B),
                                    modifier = Modifier.weight(1f)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                val isCompleted = order.status == "Completed"
                                Box(
                                    modifier = Modifier
                                        .background(
                                            if (isCompleted) Color(0xFFD1FAE5) else Color(0xFFFFEDD5),
                                            RoundedCornerShape(8.dp)
                                        )
                                        .padding(horizontal = 8.dp, vertical = 4.dp)
                                ) {
                                    Text(
                                        text = order.status,
                                        color = if (isCompleted) Color(0xFF065F46) else Color(0xFF9A3412),
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.ExtraBold
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(8.dp))

                            // Subheader: Client Name & Valuation
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = "Client: ${order.clientName}",
                                    fontSize = 13.sp,
                                    color = Color(0xFF64748B)
                                )
                                Text(
                                    text = "Rs. %,.0f".format(order.price),
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFF4F46E5)
                                )
                            }

                            // Expanded view details
                            AnimatedVisibility(visible = isExpanded) {
                                Column(modifier = Modifier.padding(top = 12.dp)) {
                                    Divider(color = Color(0xFFF1F5F9))
                                    Spacer(modifier = Modifier.height(10.dp))

                                    Text("Order Details", fontWeight = FontWeight.Bold, fontSize = 12.sp, color = Color(0xFF1E293B))
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text("Order ID: ${order.id}", fontSize = 11.sp, color = Color(0xFF64748B))
                                    Text("Client Contact: ${order.phone} | ${order.email}", fontSize = 11.sp, color = Color(0xFF64748B))
                                    
                                    Spacer(modifier = Modifier.height(10.dp))

                                    // Action buttons row: Document Vault & Specialist Assign
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        Button(
                                            onClick = { selectedOrderForVault = order },
                                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1E293B)),
                                            shape = RoundedCornerShape(8.dp),
                                            modifier = Modifier.weight(1f)
                                        ) {
                                            Icon(Icons.Default.FolderOpen, contentDescription = null, modifier = Modifier.size(16.dp))
                                            Spacer(modifier = Modifier.width(6.dp))
                                            Text("Document Vault", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                        }

                                        Button(
                                            onClick = {
                                                Toast.makeText(context, "Status change request sent", Toast.LENGTH_SHORT).show()
                                            },
                                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                                            shape = RoundedCornerShape(8.dp),
                                            modifier = Modifier.weight(1f)
                                        ) {
                                            Icon(Icons.Default.Check, contentDescription = null, modifier = Modifier.size(16.dp))
                                            Spacer(modifier = Modifier.width(6.dp))
                                            Text("Update status", fontSize = 11.sp, fontWeight = FontWeight.Bold)
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

    // 4. Simulated Document Vault Dialog overlay
    selectedOrderForVault?.let { order ->
        var vaultDocs by remember {
            mutableStateOf(
                listOf(
                    "Valuation_Briefing_Report_${order.clientName.replace(" ", "_")}.pdf" to "Approved",
                    "GST_Incorporation_Details.png" to "Verified",
                    "Identity_Verification_Aadhar.pdf" to "Pending Approval"
                )
            )
        }

        Dialog(onDismissRequest = { selectedOrderForVault = null }) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(8.dp),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Document Vault",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Black,
                            color = Color(0xFF1E293B)
                        )
                        IconButton(onClick = { selectedOrderForVault = null }) {
                            Icon(Icons.Default.Clear, contentDescription = null)
                        }
                    }

                    Text(
                        text = "Valuation credentials, reports, and identity files associated with project: ${order.serviceName}",
                        fontSize = 12.sp,
                        color = Color(0xFF64748B)
                    )

                    Divider(color = Color(0xFFEEF2F6))

                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        vaultDocs.forEach { (name, status) ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(Color(0xFFF8FAFC), RoundedCornerShape(8.dp))
                                    .padding(10.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(
                                    modifier = Modifier.weight(1f),
                                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.InsertDriveFile,
                                        contentDescription = null,
                                        tint = Color(0xFF6366F1),
                                        modifier = Modifier.size(20.dp)
                                    )
                                    Column {
                                        Text(name, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                                        Text("Status: $status", fontSize = 10.sp, color = Color(0xFF64748B))
                                    }
                                }
                                IconButton(onClick = {
                                    Toast.makeText(context, "Downloading $name...", Toast.LENGTH_SHORT).show()
                                }) {
                                    Icon(Icons.Default.Download, contentDescription = null, tint = Color(0xFF4F46E5), modifier = Modifier.size(18.dp))
                                }
                            }
                        }
                    }

                    Divider(color = Color(0xFFEEF2F6))

                    Button(
                        onClick = {
                            val newDocName = "Valuation_Completed_Certificate_${System.currentTimeMillis() % 10000}.pdf"
                            vaultDocs = vaultDocs + (newDocName to "Uploaded just now")
                            Toast.makeText(context, "Valuation Certificate generated & added to vault!", Toast.LENGTH_LONG).show()
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10B981)),
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Icon(Icons.Default.CloudUpload, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Add valuation Certificate", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }
}
