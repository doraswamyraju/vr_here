package com.sbr.vrherebms.ui.screens.customer

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BookkeepingScreen(viewModel: CustomerDashboardViewModel) {
    var selectedTab by remember { mutableStateOf("Sales") }
    var showAddDialog by remember { mutableStateOf(false) }
    var showSettingsDialog by remember { mutableStateOf(false) }
    
    // Form fields
    var docNumber by remember { mutableStateOf("") }
    var partyName by remember { mutableStateOf("") }
    var partyGstin by remember { mutableStateOf("") }
    var amount by remember { mutableStateOf("") }

    Box(modifier = Modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            contentPadding = PaddingValues(top = 16.dp, bottom = 120.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Header
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            "Bookkeeping Hub",
                            fontSize = 22.sp,
                            fontWeight = FontWeight.Black,
                            color = Color(0xFF1E293B)
                        )
                        Text(
                            "Record sales, purchases, and track GST compliance.",
                            fontSize = 13.sp,
                            color = Color(0xFF64748B),
                            modifier = Modifier.padding(top = 2.dp)
                        )
                    }
                    IconButton(onClick = { showSettingsDialog = true }) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                }
            }

            // Stats Cards
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Card(
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFECFDF5))
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text("Sales", fontSize = 11.sp, color = Color(0xFF047857), fontWeight = FontWeight.Bold)
                            Text("₹45,250", fontSize = 18.sp, color = Color(0xFF065F46), fontWeight = FontWeight.Black, modifier = Modifier.padding(top = 4.dp))
                        }
                    }

                    Card(
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFEFF6FF))
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text("Purchases", fontSize = 11.sp, color = Color(0xFF1D4ED8), fontWeight = FontWeight.Bold)
                            Text("₹12,400", fontSize = 18.sp, color = Color(0xFF1E40AF), fontWeight = FontWeight.Black, modifier = Modifier.padding(top = 4.dp))
                        }
                    }
                }
            }

            // Tabs/Selector
            item {
                TabRow(
                    selectedTabIndex = if (selectedTab == "Sales") 0 else 1,
                    containerColor = Color.Transparent,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Tab(selected = selectedTab == "Sales", onClick = { selectedTab = "Sales" }) {
                        Text("Sales", modifier = Modifier.padding(vertical = 12.dp), fontWeight = FontWeight.Bold)
                    }
                    Tab(selected = selectedTab == "Purchases", onClick = { selectedTab = "Purchases" }) {
                        Text("Purchases", modifier = Modifier.padding(vertical = 12.dp), fontWeight = FontWeight.Bold)
                    }
                }
            }

            // Quick add trigger
            item {
                Button(
                    onClick = { showAddDialog = true },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5))
                ) {
                    Icon(Icons.Default.Add, contentDescription = "Add")
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Add Bookkeeping Entry", fontWeight = FontWeight.Bold)
                }
            }

            // Records header
            item {
                Text("Recent Entries", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = Color(0xFF334155))
            }

            // Mock list items
            item {
                VoucherItem(type = "Sales", docNo = "INV-2026-001", party = "Raju Ventures Ltd", amount = "₹24,500")
            }
            item {
                VoucherItem(type = "Purchase", docNo = "PUR-98212", party = "Andhra Cement Stores", amount = "₹8,300")
            }
            item {
                VoucherItem(type = "Sales", docNo = "INV-2026-002", party = "Krishna Tech Services", amount = "₹20,750")
            }
        }

        // Add Transaction Dialog
        if (showAddDialog) {
            AlertDialog(
                onDismissRequest = { showAddDialog = false },
                title = { Text("Record Transaction", fontWeight = FontWeight.Bold) },
                text = {
                    Column(
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        // Scan simulation trigger
                        OutlinedButton(
                            onClick = {
                                partyName = "Scanned Vendor"
                                partyGstin = "37AABCR1234F1Z5"
                                docNumber = "SCN-" + (1000..9999).random()
                                amount = "15000"
                            },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFF4F46E5))
                        ) {
                            Icon(Icons.Default.Camera, contentDescription = "Scan")
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Mock Camera OCR Scan", fontWeight = FontWeight.Bold)
                        }

                        OutlinedTextField(
                            value = docNumber,
                            onValueChange = { docNumber = it },
                            label = { Text("Invoice / Doc Number") },
                            modifier = Modifier.fillMaxWidth()
                        )
                        OutlinedTextField(
                            value = partyName,
                            onValueChange = { partyName = it },
                            label = { Text("Party Name") },
                            modifier = Modifier.fillMaxWidth()
                        )
                        OutlinedTextField(
                            value = partyGstin,
                            onValueChange = { partyGstin = it },
                            label = { Text("Party GSTIN (Optional)") },
                            modifier = Modifier.fillMaxWidth()
                        )
                        OutlinedTextField(
                            value = amount,
                            onValueChange = { amount = it },
                            label = { Text("Taxable Amount (₹)") },
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                },
                confirmButton = {
                    Button(onClick = { showAddDialog = false }) {
                        Text("Record")
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showAddDialog = false }) {
                        Text("Cancel")
                    }
                }
            )
        }

        // Settings Dialog
        if (showSettingsDialog) {
            AlertDialog(
                onDismissRequest = { showSettingsDialog = false },
                title = { Text("Company Invoicing Profile", fontWeight = FontWeight.Bold) },
                text = {
                    Column(
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        var companyName by remember { mutableStateOf("") }
                        var gstin by remember { mutableStateOf("") }
                        var address by remember { mutableStateOf("") }

                        OutlinedTextField(
                            value = companyName,
                            onValueChange = { companyName = it },
                            label = { Text("Legal Business Name") },
                            modifier = Modifier.fillMaxWidth()
                        )
                        OutlinedTextField(
                            value = gstin,
                            onValueChange = { gstin = it },
                            label = { Text("Company GSTIN") },
                            modifier = Modifier.fillMaxWidth()
                        )
                        OutlinedTextField(
                            value = address,
                            onValueChange = { address = it },
                            label = { Text("Billing Address") },
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                },
                confirmButton = {
                    Button(onClick = { showSettingsDialog = false }) {
                        Text("Save")
                    }
                }
            )
        }
    }
}

@Composable
fun VoucherItem(type: String, docNo: String, party: String, amount: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFF1F5F9))
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .background(
                                color = if (type == "Sales") Color(0xFFD1FAE5) else Color(0xFFDBEAFE),
                                shape = RoundedCornerShape(6.dp)
                            )
                            .padding(horizontal = 8.dp, vertical = 4.dp)
                    ) {
                        Text(
                            text = type.uppercase(),
                            fontSize = 9.sp,
                            color = if (type == "Sales") Color(0xFF065F46) else Color(0xFF1E40AF),
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(docNo, fontSize = 14.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                }
                Text(party, fontSize = 12.sp, color = Color(0xFF64748B), modifier = Modifier.padding(top = 4.dp))
            }
            Text(amount, fontSize = 15.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
        }
    }
}
