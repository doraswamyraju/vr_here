package com.sbr.vrherebms.ui.screens.customer

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel

data class MobileTransaction(
    val id: String,
    val type: String, // Sales, Purchase, Expense
    val docNumber: String,
    val date: String,
    val partyName: String,
    val gstin: String,
    val amount: Double,
    val taxAmount: Double,
    val status: String // Paid, Pending
)

data class MobileParty(
    val id: String,
    val name: String,
    val type: String, // Customer, Vendor
    val gstin: String,
    val phone: String,
    val balance: Double
)

data class MobileStaffPayroll(
    val id: String,
    val name: String,
    val role: String,
    val netSalary: Double,
    val status: String
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BookkeepingScreen(viewModel: CustomerDashboardViewModel) {
    var selectedSubTab by remember { mutableStateOf("Dashboard") }

    val subModules = listOf(
        Triple("Dashboard", Icons.Default.Dashboard, "Overview"),
        Triple("Sales", Icons.Default.Description, "Sales Invoices"),
        Triple("Purchases", Icons.Default.ShoppingCart, "Purchase Bills"),
        Triple("Expenses", Icons.Default.TrendingDown, "Income & Expenses"),
        Triple("Bank", Icons.Default.AccountBalance, "Bank Sync"),
        Triple("Parties", Icons.Default.Group, "Customers & Vendors"),
        Triple("Payroll", Icons.Default.Badge, "Payroll & Staff"),
        Triple("Reports", Icons.Default.Assessment, "Reports & P&L")
    )

    var transactions by remember {
        mutableStateOf(
            listOf(
                MobileTransaction("1", "Sales", "INV-2026-089", "15 Sep 2026", "Sri Krishna Enterprises", "37AAACS1429B1Z0", 48500.0, 8730.0, "Paid"),
                MobileTransaction("2", "Sales", "INV-2026-090", "12 Sep 2026", "Apex Digital Solutions", "37AABCA4589D1Z3", 24000.0, 4320.0, "Pending"),
                MobileTransaction("3", "Purchase", "PUR-2026-044", "10 Sep 2026", "Tirupati Hardware & Tech", "37ABCDF6789G1Z8", 15600.0, 2808.0, "Paid"),
                MobileTransaction("4", "Expense", "EXP-2026-012", "08 Sep 2026", "Office Cloud AWS Servers", "", 6500.0, 0.0, "Paid"),
                MobileTransaction("5", "Purchase", "PUR-2026-045", "05 Sep 2026", "Venkata Logistics Co", "37BCDEF1234H1Z2", 8900.0, 1602.0, "Pending")
            )
        )
    }

    val parties = remember {
        listOf(
            MobileParty("1", "Sri Krishna Enterprises", "Customer", "37AAACS1429B1Z0", "+91 9848022338", 0.0),
            MobileParty("2", "Apex Digital Solutions", "Customer", "37AABCA4589D1Z3", "+91 9885011223", 24000.0),
            MobileParty("3", "Tirupati Hardware & Tech", "Vendor", "37ABCDF6789G1Z8", "+91 9949033445", 0.0),
            MobileParty("4", "Venkata Logistics Co", "Vendor", "37BCDEF1234H1Z2", "+91 9440055667", 8900.0)
        )
    }

    val payrollList = remember {
        listOf(
            MobileStaffPayroll("1", "Vamsi Krishna", "Accounts Executive", 33200.0, "Processed"),
            MobileStaffPayroll("2", "Anusha Reddy", "GST Associate", 26600.0, "Processed"),
            MobileStaffPayroll("3", "Karthik Naidu", "Field Executive", 19000.0, "Processed")
        )
    }

    // Modal Create Sheet
    var showCreateSheet by remember { mutableStateOf(false) }
    var createType by remember { mutableStateOf("Sales") }
    var inputParty by remember { mutableStateOf("") }
    var inputAmount by remember { mutableStateOf("") }
    var inputGstRate by remember { mutableStateOf("18%") }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFFF8FAFC)),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Header
        item {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    "Bookkeeping & AaaS Suite",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF0F172A)
                )
                Text(
                    "Executive accounting, GST invoices, bank sync & payroll management.",
                    fontSize = 12.sp,
                    color = Color.Gray
                )
            }
        }

        // Horizontal Sub-Module Chips
        item {
            LazyRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                items(subModules) { (id, icon, label) ->
                    val isSelected = selectedSubTab == id
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = if (isSelected) Color(0xFF4F46E5) else Color.White,
                        border = BorderStroke(1.dp, if (isSelected) Color(0xFF4F46E5) else Color(0xFFE2E8F0)),
                        modifier = Modifier.clickable { selectedSubTab = id }
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = icon,
                                contentDescription = null,
                                tint = if (isSelected) Color.White else Color(0xFF64748B),
                                modifier = Modifier.size(14.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = label,
                                fontSize = 11.sp,
                                fontWeight = if (isSelected) FontWeight.Black else FontWeight.Bold,
                                color = if (isSelected) Color.White else Color(0xFF334155)
                            )
                        }
                    }
                }
            }
        }

        // Sub-Module Content
        when (selectedSubTab) {
            "Dashboard" -> {
                item {
                    val totalSales = transactions.filter { it.type == "Sales" }.sumOf { it.amount }
                    val totalPurchases = transactions.filter { it.type == "Purchase" }.sumOf { it.amount }
                    val totalExpenses = transactions.filter { it.type == "Expense" }.sumOf { it.amount }
                    val netProfit = totalSales - totalPurchases - totalExpenses

                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            FinanceBox(title = "REVENUE", value = "₹${totalSales.toInt()}", icon = Icons.Default.ArrowUpward, color = Color(0xFF16A34A), modifier = Modifier.weight(1f))
                            FinanceBox(title = "PURCHASES", value = "₹${totalPurchases.toInt()}", icon = Icons.Default.ShoppingCart, color = Color(0xFF2563EB), modifier = Modifier.weight(1f))
                        }
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            FinanceBox(title = "EXPENSES", value = "₹${totalExpenses.toInt()}", icon = Icons.Default.TrendingDown, color = Color(0xFFEA580C), modifier = Modifier.weight(1f))
                            FinanceBox(title = "NET PROFIT", value = "₹${netProfit.toInt()}", icon = Icons.Default.ShowChart, color = Color(0xFF9333EA), modifier = Modifier.weight(1f))
                        }

                        // Compliance Matrix Card
                        Card(
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Default.Event, contentDescription = null, tint = Color(0xFF4F46E5), modifier = Modifier.size(18.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("Monthly Compliance Matrix", fontWeight = FontWeight.Black, fontSize = 13.sp, color = Color(0xFF0F172A))
                                }
                                ComplianceRow("GSTR-1 (Outward Supplies)", "11th Every Month", "FILED")
                                ComplianceRow("GSTR-3B (Summary Return)", "20th Every Month", "UPCOMING")
                                ComplianceRow("TDS Challan 281 Payment", "7th Every Month", "FILED")
                                ComplianceRow("Advance Tax Installment", "15th September", "ACTIVE")
                            }
                        }
                    }
                }
            }
            "Sales" -> {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("Sales Invoices", fontWeight = FontWeight.Black, fontSize = 14.sp, color = Color(0xFF0F172A))
                        Button(
                            onClick = {
                                createType = "Sales"
                                showCreateSheet = true
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Create GST Invoice", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
                items(transactions.filter { it.type == "Sales" }) { tx ->
                    MobileTxCard(tx)
                }
            }
            "Purchases" -> {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("Purchase Bills", fontWeight = FontWeight.Black, fontSize = 14.sp, color = Color(0xFF0F172A))
                        Button(
                            onClick = {
                                createType = "Purchase"
                                showCreateSheet = true
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF0F172A)),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Record Bill", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
                items(transactions.filter { it.type == "Purchase" }) { tx ->
                    MobileTxCard(tx)
                }
            }
            "Expenses" -> {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("Income & Expenses", fontWeight = FontWeight.Black, fontSize = 14.sp, color = Color(0xFF0F172A))
                        Button(
                            onClick = {
                                createType = "Expense"
                                showCreateSheet = true
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFEA580C)),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Add Voucher", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
                items(transactions.filter { it.type == "Expense" }) { tx ->
                    MobileTxCard(tx)
                }
            }
            "Bank" -> {
                item {
                    Card(
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Text("Bank Statements & Auto-Reconciliation", fontWeight = FontWeight.Black, fontSize = 14.sp, color = Color(0xFF0F172A))
                            Text("Upload bank statements (PDF / Excel) to automatically match debits and credits.", fontSize = 12.sp, color = Color.Gray)
                            Button(
                                onClick = {},
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Icon(Icons.Default.CloudUpload, contentDescription = null)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("Upload Statement (PDF/CSV)", fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }
            "Parties" -> {
                items(parties) { p ->
                    Card(
                        shape = RoundedCornerShape(14.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp).fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(38.dp)
                                    .background(if (p.type == "Customer") Color(0xFFECFDF5) else Color(0xFFEFF6FF), CircleShape),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = if (p.type == "Customer") Icons.Default.Person else Icons.Default.Business,
                                    contentDescription = null,
                                    tint = if (p.type == "Customer") Color(0xFF10B981) else Color(0xFF3B82F6),
                                    modifier = Modifier.size(20.dp)
                                )
                            }
                            Column(modifier = Modifier.weight(1f)) {
                                Text(p.name, fontWeight = FontWeight.Bold, fontSize = 13.sp, color = Color(0xFF0F172A))
                                Text(if (p.gstin.isNotEmpty()) "GSTIN: ${p.gstin}" else p.phone, fontSize = 11.sp, color = Color.Gray)
                            }
                            Column(horizontalAlignment = Alignment.End) {
                                Text(p.type.uppercase(), fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color.Gray)
                                Text(if (p.balance > 0) "₹${p.balance.toInt()} Due" else "Settled", fontSize = 11.sp, fontWeight = FontWeight.Black, color = if (p.balance > 0) Color(0xFFDC2626) else Color(0xFF16A34A))
                            }
                        }
                    }
                }
            }
            "Payroll" -> {
                items(payrollList) { emp ->
                    Card(
                        shape = RoundedCornerShape(14.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp).fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(38.dp)
                                    .background(Color(0xFFEEF2FF), CircleShape),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(Icons.Default.Badge, contentDescription = null, tint = Color(0xFF4F46E5), modifier = Modifier.size(20.dp))
                            }
                            Column(modifier = Modifier.weight(1f)) {
                                Text(emp.name, fontWeight = FontWeight.Bold, fontSize = 13.sp, color = Color(0xFF0F172A))
                                Text(emp.role, fontSize = 11.sp, color = Color.Gray)
                            }
                            Column(horizontalAlignment = Alignment.End) {
                                Text("Net ₹${emp.netSalary.toInt()}", fontSize = 12.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                Text(emp.status, fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF16A34A))
                            }
                        }
                    }
                }
            }
            "Reports" -> {
                item {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        ReportTile("Profit & Loss Statement (P&L)", "Comprehensive FY 2025-26 revenue and expense breakdown", Icons.Default.Description)
                        ReportTile("GST Liability & Input Tax Credit", "CGST, SGST, and IGST computation sheet", Icons.Default.Calculate)
                        ReportTile("Tally Prime & Zoho XML Export", "1-Click journal & ledger export for chartered accountants", Icons.Default.FileDownload)
                    }
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(100.dp))
        }
    }

    // Modal Sheet for New Invoice / Purchase / Expense
    if (showCreateSheet) {
        ModalBottomSheet(onDismissRequest = { showCreateSheet = false }) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Text("New $createType Voucher", fontWeight = FontWeight.Black, fontSize = 18.sp, color = Color(0xFF0F172A))
                OutlinedTextField(
                    value = inputParty,
                    onValueChange = { inputParty = it },
                    label = { Text("Party / Client Name") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )
                OutlinedTextField(
                    value = inputAmount,
                    onValueChange = { inputAmount = it },
                    label = { Text("Base Amount (₹)") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )
                Button(
                    onClick = {
                        val baseAmt = inputAmount.toDoubleOrNull() ?: 0.0
                        val taxAmt = baseAmt * 0.18
                        val newTx = MobileTransaction(
                            id = (transactions.size + 1).toString(),
                            type = createType,
                            docNumber = "${createType.take(3).uppercase()}-2026-${(100..999).random()}",
                            date = "Today",
                            partyName = inputParty.ifBlank { "Client" },
                            gstin = "37AAACS1429B1Z0",
                            amount = baseAmt,
                            taxAmount = taxAmt,
                            status = "Paid"
                        )
                        transactions = listOf(newTx) + transactions
                        showCreateSheet = false
                        inputParty = ""
                        inputAmount = ""
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth().height(48.dp)
                ) {
                    Text("Generate $createType Voucher", fontWeight = FontWeight.Bold)
                }
                Spacer(modifier = Modifier.height(20.dp))
            }
        }
    }
}

@Composable
private fun FinanceBox(title: String, value: String, icon: ImageVector, color: Color, modifier: Modifier = Modifier) {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
        modifier = modifier
    ) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Icon(imageVector = icon, contentDescription = null, tint = color, modifier = Modifier.size(18.dp))
            Text(title, color = Color.Gray, fontSize = 9.sp, fontWeight = FontWeight.Black)
            Text(value, color = Color(0xFF0F172A), fontSize = 17.sp, fontWeight = FontWeight.Black)
        }
    }
}

@Composable
private fun ComplianceRow(title: String, dueDate: String, status: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column {
            Text(title, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
            Text("Due: $dueDate", fontSize = 10.sp, color = Color.Gray)
        }
        Surface(
            shape = RoundedCornerShape(6.dp),
            color = if (status == "FILED") Color(0xFFD1FAE5) else Color(0xFFFEF3C7)
        ) {
            Text(
                status,
                color = if (status == "FILED") Color(0xFF065F46) else Color(0xFF92400E),
                fontSize = 9.sp,
                fontWeight = FontWeight.Black,
                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
            )
        }
    }
}

@Composable
private fun MobileTxCard(tx: MobileTransaction) {
    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(12.dp).fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(tx.docNumber, fontSize = 12.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                    Text("• ${tx.date}", fontSize = 10.sp, color = Color.Gray)
                }
                Text(tx.partyName, fontSize = 11.sp, color = Color(0xFF475569), maxLines = 1)
            }
            Column(horizontalAlignment = Alignment.End) {
                Text("₹${(tx.amount + tx.taxAmount).toInt()}", fontSize = 13.sp, fontWeight = FontWeight.Black, color = if (tx.type == "Sales") Color(0xFF16A34A) else Color(0xFF0F172A))
                Text(tx.status.uppercase(), fontSize = 8.sp, fontWeight = FontWeight.Black, color = if (tx.status == "Paid") Color(0xFF16A34A) else Color(0xFFEA580C))
            }
        }
    }
}

@Composable
private fun ReportTile(title: String, desc: String, icon: ImageVector) {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(14.dp).fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Box(
                modifier = Modifier.size(40.dp).background(Color(0xFFEEF2FF), RoundedCornerShape(10.dp)),
                contentAlignment = Alignment.Center
            ) {
                Icon(imageVector = icon, contentDescription = null, tint = Color(0xFF4F46E5), modifier = Modifier.size(20.dp))
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(title, fontWeight = FontWeight.Black, fontSize = 13.sp, color = Color(0xFF0F172A))
                Text(desc, fontSize = 11.sp, color = Color.Gray)
            }
            Icon(Icons.Default.Download, contentDescription = null, tint = Color(0xFF4F46E5))
        }
    }
}
