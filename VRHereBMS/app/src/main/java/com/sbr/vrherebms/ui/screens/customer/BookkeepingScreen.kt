package com.sbr.vrherebms.ui.screens.customer

import android.widget.Toast
import androidx.compose.animation.*
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
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel

data class MobileTransaction(
    val id: String,
    val type: String, // Sales, Purchase, Expense
    val docNumber: String,
    val date: String,
    val month: String, // e.g. "Sep 2026"
    val partyName: String,
    val gstin: String,
    val amount: Double,
    val taxAmount: Double,
    val paymentMode: String = "Bank Transfer",
    val status: String // Paid, Pending
)

data class MobileParty(
    val id: String,
    val name: String,
    val type: String, // Customer, Vendor
    val gstin: String,
    val pan: String = "",
    val phone: String,
    val address: String = "Tirupati, Andhra Pradesh",
    val balance: Double
)

data class MobileStaffPayroll(
    val id: String,
    val name: String,
    val role: String,
    val basic: Double,
    val hra: Double,
    val allowance: Double,
    val deductions: Double,
    val netSalary: Double,
    val status: String
)

data class MobileBankStatement(
    val id: String,
    val bankName: String,
    val accountNumber: String,
    val balance: Double,
    val unreconciledCount: Int,
    val lastSync: String
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BookkeepingScreen(viewModel: CustomerDashboardViewModel) {
    val context = LocalContext.current
    var selectedSubTab by remember { mutableStateOf("Dashboard") }
    var selectedMonth by remember { mutableStateOf("Sep 2026") }
    var searchQuery by remember { mutableStateOf("") }

    val monthsList = listOf(
        "Apr 2026", "May 2026", "Jun 2026", "Jul 2026", "Aug 2026", "Sep 2026",
        "Oct 2026", "Nov 2026", "Dec 2026", "Jan 2027", "Feb 2027", "Mar 2027",
        "All Months (FY 26-27)"
    )

    val subModules = listOf(
        Triple("Dashboard", Icons.Default.Dashboard, "Dashboard"),
        Triple("Sales", Icons.Default.Description, "Sales Invoices"),
        Triple("Purchases", Icons.Default.ShoppingCart, "Purchase Bills"),
        Triple("Expenses", Icons.Default.TrendingDown, "Expenses"),
        Triple("Bank", Icons.Default.AccountBalance, "Bank Sync"),
        Triple("Parties", Icons.Default.Group, "Parties Master"),
        Triple("Payroll", Icons.Default.Badge, "Staff Payroll"),
        Triple("Reports", Icons.Default.Assessment, "Financial Reports")
    )

    // Master dataset
    var transactions by remember {
        mutableStateOf(
            listOf(
                MobileTransaction("1", "Sales", "INV-2026-089", "15 Sep 2026", "Sep 2026", "Sri Krishna Enterprises", "37AAACS1429B1Z0", 48500.0, 8730.0, "Bank Transfer", "Paid"),
                MobileTransaction("2", "Sales", "INV-2026-090", "12 Sep 2026", "Sep 2026", "Apex Digital Solutions", "37AABCA4589D1Z3", 24000.0, 4320.0, "UPI", "Pending"),
                MobileTransaction("3", "Purchase", "PUR-2026-044", "10 Sep 2026", "Sep 2026", "Tirupati Hardware & Tech", "37ABCDF6789G1Z8", 15600.0, 2808.0, "Bank Transfer", "Paid"),
                MobileTransaction("4", "Expense", "EXP-2026-012", "08 Sep 2026", "Sep 2026", "Office Cloud AWS Servers", "", 6500.0, 0.0, "Corporate Card", "Paid"),
                MobileTransaction("5", "Purchase", "PUR-2026-045", "05 Sep 2026", "Sep 2026", "Venkata Logistics Co", "37BCDEF1234H1Z2", 8900.0, 1602.0, "Bank Transfer", "Pending"),
                MobileTransaction("6", "Sales", "INV-2026-078", "24 Aug 2026", "Aug 2026", "Chittoor Agro Corp", "37AABCC8921K1Z5", 62000.0, 11160.0, "Bank Transfer", "Paid"),
                MobileTransaction("7", "Expense", "EXP-2026-010", "15 Aug 2026", "Aug 2026", "Office Space Rent", "", 25000.0, 0.0, "Bank Transfer", "Paid")
            )
        )
    }

    var parties by remember {
        mutableStateOf(
            listOf(
                MobileParty("1", "Sri Krishna Enterprises", "Customer", "37AAACS1429B1Z0", "AAACS1429B", "+91 9848022338", "Industrial Estate, Tirupati", 0.0),
                MobileParty("2", "Apex Digital Solutions", "Customer", "37AABCA4589D1Z3", "AABCA4589D", "+91 9885011223", "Bhavani Nagar, Tirupati", 28320.0),
                MobileParty("3", "Tirupati Hardware & Tech", "Vendor", "37ABCDF6789G1Z8", "ABCDF6789G", "+91 9949033445", "Gandhi Road, Tirupati", 0.0),
                MobileParty("4", "Venkata Logistics Co", "Vendor", "37BCDEF1234H1Z2", "BCDEF1234H", "+91 9440055667", "Renigunta Road, Tirupati", 10502.0),
                MobileParty("5", "Chittoor Agro Corp", "Customer", "37AABCC8921K1Z5", "AABCC8921K", "+91 9700011223", "M.B.T. Road, Chittoor", 0.0)
            )
        )
    }

    val payrollList = remember {
        listOf(
            MobileStaffPayroll("1", "Vamsi Krishna", "Accounts Executive", 25000.0, 7500.0, 3500.0, 2800.0, 33200.0, "Processed"),
            MobileStaffPayroll("2", "Anusha Reddy", "GST Associate", 20000.0, 6000.0, 2800.0, 2200.0, 26600.0, "Processed"),
            MobileStaffPayroll("3", "Karthik Naidu", "Field Executive", 14000.0, 4200.0, 2300.0, 1500.0, 19000.0, "Processed")
        )
    }

    val bankAccounts = remember {
        listOf(
            MobileBankStatement("1", "HDFC Bank Current A/c", "•••• 4589", 342680.0, 2, "Synced Today 09:30 AM"),
            MobileBankStatement("2", "ICICI Bank Tax Reserve", "•••• 7812", 118400.0, 0, "Synced Yesterday")
        )
    }

    // Modals state
    var showCreateSalesDialog by remember { mutableStateOf(false) }
    var showCreatePurchaseDialog by remember { mutableStateOf(false) }
    var showCreateExpenseDialog by remember { mutableStateOf(false) }
    var showAddPartyDialog by remember { mutableStateOf(false) }
    var previewInvoice by remember { mutableStateOf<MobileTransaction?>(null) }
    var previewPayslip by remember { mutableStateOf<MobileStaffPayroll?>(null) }

    // Filter transactions by selected month
    val filteredTx = remember(transactions, selectedMonth, searchQuery) {
        transactions.filter { tx ->
            val monthMatch = if (selectedMonth.startsWith("All")) true else tx.month == selectedMonth
            val searchMatch = searchQuery.isBlank() ||
                tx.docNumber.contains(searchQuery, ignoreCase = true) ||
                tx.partyName.contains(searchQuery, ignoreCase = true)
            monthMatch && searchMatch
        }
    }

    val primaryIndigo = Color(0xFF4F46E5)
    val lightSlate = Color(0xFFF8FAFC)
    val textDark = Color(0xFF0F172A)
    val textMuted = Color(0xFF64748B)

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(lightSlate),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // 1. Suite Header Banner
        item {
            Card(
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
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
                                    .size(42.dp)
                                    .background(primaryIndigo.copy(alpha = 0.1f), RoundedCornerShape(12.dp)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(Icons.Default.Book, contentDescription = null, tint = primaryIndigo, modifier = Modifier.size(24.dp))
                            }
                            Column {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                    Text("Bookkeeping & AaaS", fontSize = 16.sp, fontWeight = FontWeight.Black, color = textDark)
                                    Surface(
                                        color = Color(0xFFDCFCE7),
                                        shape = RoundedCornerShape(6.dp)
                                    ) {
                                        Text("LIVE GST", color = Color(0xFF166534), fontSize = 9.sp, fontWeight = FontWeight.Black, modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp))
                                    }
                                }
                                Text("Executive Accounting, Invoices, Bank Sync & Payroll", fontSize = 11.sp, color = textMuted)
                            }
                        }
                    }

                    // Month Selector Chips Bar
                    Text("FINANCIAL PERIOD:", fontSize = 9.5.sp, fontWeight = FontWeight.Black, color = textMuted, letterSpacing = 0.5.sp)
                    LazyRow(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        items(monthsList) { m ->
                            val isSel = selectedMonth == m
                            Surface(
                                shape = RoundedCornerShape(8.dp),
                                color = if (isSel) primaryIndigo else Color(0xFFF1F5F9),
                                border = BorderStroke(1.dp, if (isSel) primaryIndigo else Color(0xFFE2E8F0)),
                                modifier = Modifier.clickable { selectedMonth = m }
                            ) {
                                Text(
                                    text = m,
                                    fontSize = 11.sp,
                                    fontWeight = if (isSel) FontWeight.Black else FontWeight.Medium,
                                    color = if (isSel) Color.White else Color(0xFF334155),
                                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
                                )
                            }
                        }
                    }
                }
            }
        }

        // 2. Sub-Modules Navigation Tabs Bar
        item {
            LazyRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                items(subModules) { (id, icon, label) ->
                    val isSelected = selectedSubTab == id
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = if (isSelected) primaryIndigo else Color.White,
                        border = BorderStroke(1.dp, if (isSelected) primaryIndigo else Color(0xFFE2E8F0)),
                        shadowElevation = if (isSelected) 3.dp else 1.dp,
                        modifier = Modifier.clickable { selectedSubTab = id }
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Icon(
                                imageVector = icon,
                                contentDescription = null,
                                tint = if (isSelected) Color.White else primaryIndigo,
                                modifier = Modifier.size(15.dp)
                            )
                            Text(
                                text = label,
                                fontSize = 11.5.sp,
                                fontWeight = if (isSelected) FontWeight.Black else FontWeight.Bold,
                                color = if (isSelected) Color.White else textDark
                            )
                        }
                    }
                }
            }
        }

        // 3. Sub-Module Content Areas
        when (selectedSubTab) {
            "Dashboard" -> {
                item {
                    val totalSales = filteredTx.filter { it.type == "Sales" }.sumOf { it.amount + it.taxAmount }
                    val totalPurchases = filteredTx.filter { it.type == "Purchase" }.sumOf { it.amount + it.taxAmount }
                    val totalExpenses = filteredTx.filter { it.type == "Expense" }.sumOf { it.amount }
                    val netProfit = totalSales - totalPurchases - totalExpenses

                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        // 4 Core Financial KPI Tiles
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            FinanceBox(title = "COLLECTIONS / SALES", value = "₹${totalSales.toInt()}", icon = Icons.Default.ArrowUpward, color = Color(0xFF16A34A), modifier = Modifier.weight(1f))
                            FinanceBox(title = "VENDOR PAYABLES", value = "₹${totalPurchases.toInt()}", icon = Icons.Default.ShoppingCart, color = Color(0xFF2563EB), modifier = Modifier.weight(1f))
                        }
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            FinanceBox(title = "OPERATING EXPENSES", value = "₹${totalExpenses.toInt()}", icon = Icons.Default.TrendingDown, color = Color(0xFFEA580C), modifier = Modifier.weight(1f))
                            FinanceBox(title = "NET WORKING MARGIN", value = "₹${netProfit.toInt()}", icon = Icons.Default.ShowChart, color = if (netProfit >= 0) Color(0xFF9333EA) else Color(0xFFDC2626), modifier = Modifier.weight(1f))
                        }

                        // Compliance Matrix Card (1:1 with Web)
                        Card(
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                            elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Icon(Icons.Default.Event, contentDescription = null, tint = primaryIndigo, modifier = Modifier.size(18.dp))
                                        Text("Monthly Filings Compliance Matrix", fontWeight = FontWeight.Black, fontSize = 13.sp, color = textDark)
                                    }
                                    Text("FY 2026-27", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = primaryIndigo)
                                }
                                HorizontalDivider(color = Color(0xFFF1F5F9))
                                ComplianceRow("GSTR-1 (Outward Supplies)", "11th Every Month", "FILED")
                                ComplianceRow("GSTR-3B (Summary Return)", "20th Every Month", "UPCOMING")
                                ComplianceRow("TDS Challan 281 Payment", "7th Every Month", "FILED")
                                ComplianceRow("Advance Tax Q2 Installment", "15th September", "ACTIVE")
                                ComplianceRow("ROC Annual Return (MGT-7A)", "30th October", "SCHEDULED")
                            }
                        }

                        // Recent Vouchers Header
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("Recent Vouchers ($selectedMonth)", fontWeight = FontWeight.Black, fontSize = 13.sp, color = textDark)
                            Text("${filteredTx.size} Entries", fontSize = 11.sp, color = textMuted, fontWeight = FontWeight.Bold)
                        }
                    }
                }

                items(filteredTx.take(5)) { tx ->
                    MobileTxCard(tx, onClick = { previewInvoice = tx })
                }
            }

            "Sales" -> {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text("Sales Invoices", fontWeight = FontWeight.Black, fontSize = 15.sp, color = textDark)
                            Text("GST compliant outward tax invoices", fontSize = 11.sp, color = textMuted)
                        }
                        Button(
                            onClick = { showCreateSalesDialog = true },
                            colors = ButtonDefaults.buttonColors(containerColor = primaryIndigo),
                            shape = RoundedCornerShape(10.dp),
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                        ) {
                            Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(15.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Create Invoice", fontSize = 11.5.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }

                val salesList = filteredTx.filter { it.type == "Sales" }
                if (salesList.isEmpty()) {
                    item { EmptyStateBox("No sales invoices found for $selectedMonth") }
                } else {
                    items(salesList) { tx ->
                        MobileTxCard(tx, onClick = { previewInvoice = tx })
                    }
                }
            }

            "Purchases" -> {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text("Purchase Bills", fontWeight = FontWeight.Black, fontSize = 15.sp, color = textDark)
                            Text("Inward vendor bills & Input Tax Credit (ITC)", fontSize = 11.sp, color = textMuted)
                        }
                        Button(
                            onClick = { showCreatePurchaseDialog = true },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF0F172A)),
                            shape = RoundedCornerShape(10.dp),
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                        ) {
                            Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(15.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Record Bill", fontSize = 11.5.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }

                val purchaseList = filteredTx.filter { it.type == "Purchase" }
                if (purchaseList.isEmpty()) {
                    item { EmptyStateBox("No purchase bills found for $selectedMonth") }
                } else {
                    items(purchaseList) { tx ->
                        MobileTxCard(tx, onClick = { previewInvoice = tx })
                    }
                }
            }

            "Expenses" -> {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text("Operating Expenses", fontWeight = FontWeight.Black, fontSize = 15.sp, color = textDark)
                            Text("Direct & Indirect cash outflows", fontSize = 11.sp, color = textMuted)
                        }
                        Button(
                            onClick = { showCreateExpenseDialog = true },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFEA580C)),
                            shape = RoundedCornerShape(10.dp),
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                        ) {
                            Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(15.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Add Expense", fontSize = 11.5.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }

                val expenseList = filteredTx.filter { it.type == "Expense" }
                if (expenseList.isEmpty()) {
                    item { EmptyStateBox("No expenses recorded for $selectedMonth") }
                } else {
                    items(expenseList) { tx ->
                        MobileTxCard(tx, onClick = { previewInvoice = tx })
                    }
                }
            }

            "Bank" -> {
                item {
                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Card(
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                            elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Icon(Icons.Default.Sync, contentDescription = null, tint = primaryIndigo)
                                    Text("Bank Statements & Auto-Reconciliation", fontWeight = FontWeight.Black, fontSize = 14.sp, color = textDark)
                                }
                                Text("Upload your monthly bank statements (PDF or Excel) for automated ledger matching against GST invoices.", fontSize = 11.5.sp, color = textMuted)
                                
                                Button(
                                    onClick = {
                                        Toast.makeText(context, "Select Bank Statement PDF/CSV from storage", Toast.LENGTH_SHORT).show()
                                    },
                                    colors = ButtonDefaults.buttonColors(containerColor = primaryIndigo),
                                    shape = RoundedCornerShape(10.dp),
                                    modifier = Modifier.fillMaxWidth().height(42.dp)
                                ) {
                                    Icon(Icons.Default.CloudUpload, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Upload Statement (PDF / Excel)", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                                }
                            }
                        }

                        Text("Connected Bank Accounts", fontWeight = FontWeight.Black, fontSize = 13.sp, color = textDark)
                    }
                }

                items(bankAccounts) { b ->
                    Card(
                        shape = RoundedCornerShape(14.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(14.dp).fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Box(
                                modifier = Modifier.size(42.dp).background(Color(0xFFEFF6FF), CircleShape),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(Icons.Default.AccountBalance, contentDescription = null, tint = Color(0xFF2563EB), modifier = Modifier.size(22.dp))
                            }
                            Column(modifier = Modifier.weight(1f)) {
                                Text(b.bankName, fontWeight = FontWeight.Bold, fontSize = 13.sp, color = textDark)
                                Text(b.accountNumber, fontSize = 11.sp, color = textMuted)
                                Text(b.lastSync, fontSize = 9.sp, color = Color(0xFF16A34A), fontWeight = FontWeight.SemiBold)
                            }
                            Column(horizontalAlignment = Alignment.End) {
                                Text("₹${b.balance.toInt()}", fontWeight = FontWeight.Black, fontSize = 14.sp, color = textDark)
                                if (b.unreconciledCount > 0) {
                                    Surface(color = Color(0xFFFEF3C7), shape = RoundedCornerShape(6.dp)) {
                                        Text("${b.unreconciledCount} Unmatched", color = Color(0xFFB45309), fontSize = 9.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp))
                                    }
                                } else {
                                    Surface(color = Color(0xFFDCFCE7), shape = RoundedCornerShape(6.dp)) {
                                        Text("Reconciled", color = Color(0xFF15803D), fontSize = 9.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp))
                                    }
                                }
                            }
                        }
                    }
                }
            }

            "Parties" -> {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text("Parties Master", fontWeight = FontWeight.Black, fontSize = 15.sp, color = textDark)
                            Text("Customers & Vendors Directory", fontSize = 11.sp, color = textMuted)
                        }
                        Button(
                            onClick = { showAddPartyDialog = true },
                            colors = ButtonDefaults.buttonColors(containerColor = primaryIndigo),
                            shape = RoundedCornerShape(10.dp),
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                        ) {
                            Icon(Icons.Default.PersonAdd, contentDescription = null, modifier = Modifier.size(15.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Add Party", fontSize = 11.5.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }

                items(parties) { p ->
                    Card(
                        shape = RoundedCornerShape(14.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
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
                                Text(p.name, fontWeight = FontWeight.Bold, fontSize = 13.sp, color = textDark)
                                Text(if (p.gstin.isNotEmpty()) "GSTIN: ${p.gstin}" else p.phone, fontSize = 11.sp, color = textMuted)
                                Text(p.address, fontSize = 9.sp, color = Color.Gray, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                            Column(horizontalAlignment = Alignment.End) {
                                Surface(
                                    color = if (p.type == "Customer") Color(0xFFE0F2FE) else Color(0xFFF3E8FF),
                                    shape = RoundedCornerShape(6.dp)
                                ) {
                                    Text(p.type.uppercase(), fontSize = 8.sp, fontWeight = FontWeight.Black, color = if (p.type == "Customer") Color(0xFF0369A1) else Color(0xFF7E22CE), modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp))
                                }
                                Spacer(modifier = Modifier.height(3.dp))
                                Text(if (p.balance > 0) "₹${p.balance.toInt()} Due" else "Settled", fontSize = 11.sp, fontWeight = FontWeight.Black, color = if (p.balance > 0) Color(0xFFDC2626) else Color(0xFF16A34A))
                            }
                        }
                    }
                }
            }

            "Payroll" -> {
                item {
                    Card(
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Icon(Icons.Default.Badge, contentDescription = null, tint = primaryIndigo)
                                    Text("Staff Payroll & Salary Disbursals", fontWeight = FontWeight.Black, fontSize = 14.sp, color = textDark)
                                }
                                Surface(color = Color(0xFFDCFCE7), shape = RoundedCornerShape(6.dp)) {
                                    Text("3 Active Staff", color = Color(0xFF15803D), fontSize = 9.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                                }
                            }
                            Text("Monthly salary calculations including Basic, HRA, PF/ESI deductions and direct payslip downloads.", fontSize = 11.5.sp, color = textMuted)
                        }
                    }
                }

                items(payrollList) { emp ->
                    Card(
                        shape = RoundedCornerShape(14.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                        modifier = Modifier.fillMaxWidth().clickable { previewPayslip = emp }
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp).fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Box(
                                modifier = Modifier.size(38.dp).background(Color(0xFFEEF2FF), CircleShape),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(Icons.Default.Badge, contentDescription = null, tint = primaryIndigo, modifier = Modifier.size(20.dp))
                            }
                            Column(modifier = Modifier.weight(1f)) {
                                Text(emp.name, fontWeight = FontWeight.Bold, fontSize = 13.sp, color = textDark)
                                Text(emp.role, fontSize = 11.sp, color = textMuted)
                                Text("Basic: ₹${emp.basic.toInt()} • HRA: ₹${emp.hra.toInt()}", fontSize = 9.sp, color = Color.Gray)
                            }
                            Column(horizontalAlignment = Alignment.End) {
                                Text("Net ₹${emp.netSalary.toInt()}", fontSize = 12.sp, fontWeight = FontWeight.Black, color = textDark)
                                Surface(color = Color(0xFFDCFCE7), shape = RoundedCornerShape(6.dp)) {
                                    Text("View Slip", fontSize = 8.5.sp, fontWeight = FontWeight.Bold, color = Color(0xFF15803D), modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp))
                                }
                            }
                        }
                    }
                }
            }

            "Reports" -> {
                item {
                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("Financial Reports & Exports", fontWeight = FontWeight.Black, fontSize = 15.sp, color = textDark)
                        Text("Generate CA-ready audited statements and 1-click accounting ERP XML sync files.", fontSize = 11.sp, color = textMuted)

                        ReportTile("Profit & Loss Statement (P&L)", "Comprehensive FY 2026-27 income vs expense schedule", Icons.Default.Description) {
                            Toast.makeText(context, "Exporting P&L Statement (PDF)...", Toast.LENGTH_SHORT).show()
                        }
                        ReportTile("Balance Sheet (Assets vs Liabilities)", "Audited schedule of capital, fixed assets & current bank reserves", Icons.Default.AccountBalance) {
                            Toast.makeText(context, "Exporting Balance Sheet (PDF)...", Toast.LENGTH_SHORT).show()
                        }
                        ReportTile("GST Liability & ITC Summary (GSTR-3B)", "Output tax liability vs Input Tax Credit computation sheet", Icons.Default.Calculate) {
                            Toast.makeText(context, "Exporting GST Computation Summary...", Toast.LENGTH_SHORT).show()
                        }
                        ReportTile("Tally Prime & Zoho Books XML Export", "1-Click journal, sales & purchase vouchers for Chartered Accountants", Icons.Default.FileDownload) {
                            Toast.makeText(context, "Exporting Tally Prime XML Data...", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(100.dp))
        }
    }

    // Modal Sheet: Create Sales Invoice
    if (showCreateSalesDialog) {
        var partyInput by remember { mutableStateOf("") }
        var gstinInput by remember { mutableStateOf("") }
        var amountInput by remember { mutableStateOf("") }
        var gstRateInput by remember { mutableStateOf("18%") }

        ModalBottomSheet(onDismissRequest = { showCreateSalesDialog = false }) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text("Create GST Sales Invoice", fontWeight = FontWeight.Black, fontSize = 18.sp, color = textDark)
                Text("Generate GST compliant tax invoice with automated tax splitting.", fontSize = 11.5.sp, color = textMuted)

                OutlinedTextField(
                    value = partyInput,
                    onValueChange = { partyInput = it },
                    label = { Text("Customer / Client Name") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp)
                )

                OutlinedTextField(
                    value = gstinInput,
                    onValueChange = { gstinInput = it },
                    label = { Text("Customer GSTIN (Optional)") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp)
                )

                OutlinedTextField(
                    value = amountInput,
                    onValueChange = { amountInput = it },
                    label = { Text("Taxable Base Value (₹)") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp)
                )

                Button(
                    onClick = {
                        val base = amountInput.toDoubleOrNull() ?: 0.0
                        if (partyInput.isBlank() || base <= 0) {
                            Toast.makeText(context, "Please enter valid party name and amount", Toast.LENGTH_SHORT).show()
                            return@Button
                        }
                        val tax = base * 0.18
                        val newTx = MobileTransaction(
                            id = (transactions.size + 1).toString(),
                            type = "Sales",
                            docNumber = "INV-2026-${(100..999).random()}",
                            date = "Today",
                            month = selectedMonth.ifBlank { "Sep 2026" },
                            partyName = partyInput,
                            gstin = gstinInput.ifBlank { "Unregistered" },
                            amount = base,
                            taxAmount = tax,
                            paymentMode = "Bank Transfer",
                            status = "Paid"
                        )
                        transactions = listOf(newTx) + transactions
                        showCreateSalesDialog = false
                        Toast.makeText(context, "Sales Invoice Generated Successfully!", Toast.LENGTH_SHORT).show()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = primaryIndigo),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth().height(48.dp)
                ) {
                    Text("Generate & Save Invoice", fontWeight = FontWeight.Bold)
                }
                Spacer(modifier = Modifier.height(20.dp))
            }
        }
    }

    // Modal Sheet: Record Purchase Bill
    if (showCreatePurchaseDialog) {
        var vendorInput by remember { mutableStateOf("") }
        var billNoInput by remember { mutableStateOf("") }
        var amountInput by remember { mutableStateOf("") }

        ModalBottomSheet(onDismissRequest = { showCreatePurchaseDialog = false }) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text("Record Vendor Purchase Bill", fontWeight = FontWeight.Black, fontSize = 18.sp, color = textDark)
                Text("Record inward tax invoices to claim Input Tax Credit (ITC).", fontSize = 11.5.sp, color = textMuted)

                OutlinedTextField(
                    value = vendorInput,
                    onValueChange = { vendorInput = it },
                    label = { Text("Vendor Name") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp)
                )

                OutlinedTextField(
                    value = billNoInput,
                    onValueChange = { billNoInput = it },
                    label = { Text("Vendor Bill / Invoice #") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp)
                )

                OutlinedTextField(
                    value = amountInput,
                    onValueChange = { amountInput = it },
                    label = { Text("Bill Amount (₹)") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp)
                )

                Button(
                    onClick = {
                        val base = amountInput.toDoubleOrNull() ?: 0.0
                        if (vendorInput.isBlank() || base <= 0) {
                            Toast.makeText(context, "Please enter valid vendor and amount", Toast.LENGTH_SHORT).show()
                            return@Button
                        }
                        val tax = base * 0.18
                        val newTx = MobileTransaction(
                            id = (transactions.size + 1).toString(),
                            type = "Purchase",
                            docNumber = billNoInput.ifBlank { "PUR-2026-${(100..999).random()}" },
                            date = "Today",
                            month = selectedMonth.ifBlank { "Sep 2026" },
                            partyName = vendorInput,
                            gstin = "37ABCDF6789G1Z8",
                            amount = base,
                            taxAmount = tax,
                            paymentMode = "Bank Transfer",
                            status = "Paid"
                        )
                        transactions = listOf(newTx) + transactions
                        showCreatePurchaseDialog = false
                        Toast.makeText(context, "Purchase Bill Saved Successfully!", Toast.LENGTH_SHORT).show()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF0F172A)),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth().height(48.dp)
                ) {
                    Text("Save Purchase Record", fontWeight = FontWeight.Bold)
                }
                Spacer(modifier = Modifier.height(20.dp))
            }
        }
    }

    // Modal Sheet: Add Expense
    if (showCreateExpenseDialog) {
        var expenseCategory by remember { mutableStateOf("Office Rent") }
        var amountInput by remember { mutableStateOf("") }
        var modeInput by remember { mutableStateOf("Bank Transfer") }

        ModalBottomSheet(onDismissRequest = { showCreateExpenseDialog = false }) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text("Add Operating Expense", fontWeight = FontWeight.Black, fontSize = 18.sp, color = textDark)
                Text("Record daily operating expenditures and overheads.", fontSize = 11.5.sp, color = textMuted)

                OutlinedTextField(
                    value = expenseCategory,
                    onValueChange = { expenseCategory = it },
                    label = { Text("Expense Category / Description") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp)
                )

                OutlinedTextField(
                    value = amountInput,
                    onValueChange = { amountInput = it },
                    label = { Text("Amount Paid (₹)") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp)
                )

                Button(
                    onClick = {
                        val base = amountInput.toDoubleOrNull() ?: 0.0
                        if (expenseCategory.isBlank() || base <= 0) {
                            Toast.makeText(context, "Please enter valid expense details", Toast.LENGTH_SHORT).show()
                            return@Button
                        }
                        val newTx = MobileTransaction(
                            id = (transactions.size + 1).toString(),
                            type = "Expense",
                            docNumber = "EXP-2026-${(100..999).random()}",
                            date = "Today",
                            month = selectedMonth.ifBlank { "Sep 2026" },
                            partyName = expenseCategory,
                            gstin = "",
                            amount = base,
                            taxAmount = 0.0,
                            paymentMode = modeInput,
                            status = "Paid"
                        )
                        transactions = listOf(newTx) + transactions
                        showCreateExpenseDialog = false
                        Toast.makeText(context, "Expense Voucher Created!", Toast.LENGTH_SHORT).show()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFEA580C)),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth().height(48.dp)
                ) {
                    Text("Record Expense Voucher", fontWeight = FontWeight.Bold)
                }
                Spacer(modifier = Modifier.height(20.dp))
            }
        }
    }

    // Modal Sheet: Add Party
    if (showAddPartyDialog) {
        var partyName by remember { mutableStateOf("") }
        var partyType by remember { mutableStateOf("Customer") }
        var gstin by remember { mutableStateOf("") }
        var phone by remember { mutableStateOf("") }

        ModalBottomSheet(onDismissRequest = { showAddPartyDialog = false }) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text("Add Master Party", fontWeight = FontWeight.Black, fontSize = 18.sp, color = textDark)
                Text("Register customer or vendor master record.", fontSize = 11.5.sp, color = textMuted)

                OutlinedTextField(
                    value = partyName,
                    onValueChange = { partyName = it },
                    label = { Text("Business / Party Name") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp)
                )

                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    listOf("Customer", "Vendor").forEach { t ->
                        val isSel = partyType == t
                        Surface(
                            shape = RoundedCornerShape(8.dp),
                            color = if (isSel) primaryIndigo else Color(0xFFF1F5F9),
                            modifier = Modifier.weight(1f).clickable { partyType = t }
                        ) {
                            Text(
                                text = t,
                                textAlign = TextAlign.Center,
                                color = if (isSel) Color.White else textDark,
                                fontWeight = FontWeight.Bold,
                                fontSize = 12.sp,
                                modifier = Modifier.padding(vertical = 10.dp)
                            )
                        }
                    }
                }

                OutlinedTextField(
                    value = gstin,
                    onValueChange = { gstin = it },
                    label = { Text("GSTIN") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp)
                )

                OutlinedTextField(
                    value = phone,
                    onValueChange = { phone = it },
                    label = { Text("Contact Phone") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp)
                )

                Button(
                    onClick = {
                        if (partyName.isBlank()) {
                            Toast.makeText(context, "Party Name is required", Toast.LENGTH_SHORT).show()
                            return@Button
                        }
                        val newParty = MobileParty(
                            id = (parties.size + 1).toString(),
                            name = partyName,
                            type = partyType,
                            gstin = gstin,
                            phone = phone.ifBlank { "+91 9848022338" },
                            balance = 0.0
                        )
                        parties = parties + newParty
                        showAddPartyDialog = false
                        Toast.makeText(context, "Party Saved to Master Directory!", Toast.LENGTH_SHORT).show()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = primaryIndigo),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth().height(48.dp)
                ) {
                    Text("Save Master Party", fontWeight = FontWeight.Bold)
                }
                Spacer(modifier = Modifier.height(20.dp))
            }
        }
    }

    // Modal Dialog: Preview GST Invoice
    if (previewInvoice != null) {
        val inv = previewInvoice!!
        Dialog(onDismissRequest = { previewInvoice = null }) {
            Card(
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                modifier = Modifier.fillMaxWidth().padding(10.dp)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text("TAX INVOICE", fontSize = 16.sp, fontWeight = FontWeight.Black, color = textDark)
                            Text(inv.docNumber, fontSize = 12.sp, color = primaryIndigo, fontWeight = FontWeight.Bold)
                        }
                        IconButton(onClick = { previewInvoice = null }) {
                            Icon(Icons.Default.Close, contentDescription = null, tint = textMuted)
                        }
                    }

                    HorizontalDivider(color = Color(0xFFF1F5F9))

                    Text("Billed To: ${inv.partyName}", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = textDark)
                    if (inv.gstin.isNotEmpty()) {
                        Text("GSTIN: ${inv.gstin}", fontSize = 11.sp, color = textMuted)
                    }
                    Text("Date: ${inv.date}", fontSize = 11.sp, color = textMuted)

                    HorizontalDivider(color = Color(0xFFF1F5F9))

                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Taxable Amount", fontSize = 12.sp, color = textMuted)
                        Text("₹${inv.amount.toInt()}", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = textDark)
                    }

                    if (inv.taxAmount > 0) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("CGST (9%) + SGST (9%)", fontSize = 12.sp, color = textMuted)
                            Text("₹${inv.taxAmount.toInt()}", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = textDark)
                        }
                    }

                    HorizontalDivider(color = Color(0xFFE2E8F0))

                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Grand Total", fontSize = 14.sp, fontWeight = FontWeight.Black, color = textDark)
                        Text("₹${(inv.amount + inv.taxAmount).toInt()}", fontSize = 16.sp, fontWeight = FontWeight.Black, color = primaryIndigo)
                    }

                    Button(
                        onClick = {
                            Toast.makeText(context, "Downloading PDF: ${inv.docNumber}...", Toast.LENGTH_SHORT).show()
                            previewInvoice = null
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = primaryIndigo),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth().height(44.dp)
                    ) {
                        Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Download PDF Invoice", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }

    // Modal Dialog: Preview Staff Payslip
    if (previewPayslip != null) {
        val slip = previewPayslip!!
        Dialog(onDismissRequest = { previewPayslip = null }) {
            Card(
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                modifier = Modifier.fillMaxWidth().padding(10.dp)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text("SALARY SLIP", fontSize = 16.sp, fontWeight = FontWeight.Black, color = textDark)
                            Text("Month: September 2026", fontSize = 11.sp, color = textMuted)
                        }
                        IconButton(onClick = { previewPayslip = null }) {
                            Icon(Icons.Default.Close, contentDescription = null, tint = textMuted)
                        }
                    }

                    HorizontalDivider(color = Color(0xFFF1F5F9))

                    Text(slip.name, fontWeight = FontWeight.Black, fontSize = 14.sp, color = textDark)
                    Text("Designation: ${slip.role}", fontSize = 11.5.sp, color = textMuted)

                    HorizontalDivider(color = Color(0xFFF1F5F9))

                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Basic Salary", fontSize = 12.sp, color = textMuted)
                        Text("₹${slip.basic.toInt()}", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = textDark)
                    }
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("House Rent Allowance (HRA)", fontSize = 12.sp, color = textMuted)
                        Text("₹${slip.hra.toInt()}", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = textDark)
                    }
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Special Allowance", fontSize = 12.sp, color = textMuted)
                        Text("₹${slip.allowance.toInt()}", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = textDark)
                    }
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Statutory Deductions (PF/ESI/PT)", fontSize = 12.sp, color = Color(0xFFDC2626))
                        Text("- ₹${slip.deductions.toInt()}", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFFDC2626))
                    }

                    HorizontalDivider(color = Color(0xFFE2E8F0))

                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Net Salary Payable", fontSize = 14.sp, fontWeight = FontWeight.Black, color = textDark)
                        Text("₹${slip.netSalary.toInt()}", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFF16A34A))
                    }

                    Button(
                        onClick = {
                            Toast.makeText(context, "Downloading Payslip for ${slip.name}...", Toast.LENGTH_SHORT).show()
                            previewPayslip = null
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = primaryIndigo),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth().height(44.dp)
                    ) {
                        Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Download Payslip (PDF)", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }
}

@Composable
private fun FinanceBox(title: String, value: String, icon: ImageVector, color: Color, modifier: Modifier = Modifier) {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
        modifier = modifier
    ) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Icon(imageVector = icon, contentDescription = null, tint = color, modifier = Modifier.size(18.dp))
            Text(title, color = Color(0xFF64748B), fontSize = 9.sp, fontWeight = FontWeight.Black)
            Text(value, color = Color(0xFF0F172A), fontSize = 16.sp, fontWeight = FontWeight.Black)
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
            Text(title, fontSize = 11.5.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
            Text("Due: $dueDate", fontSize = 9.5.sp, color = Color.Gray)
        }
        Surface(
            shape = RoundedCornerShape(6.dp),
            color = when (status) {
                "FILED" -> Color(0xFFD1FAE5)
                "ACTIVE" -> Color(0xFFEFF6FF)
                else -> Color(0xFFFEF3C7)
            }
        ) {
            Text(
                status,
                color = when (status) {
                    "FILED" -> Color(0xFF065F46)
                    "ACTIVE" -> Color(0xFF1D4ED8)
                    else -> Color(0xFF92400E)
                },
                fontSize = 8.5.sp,
                fontWeight = FontWeight.Black,
                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
            )
        }
    }
}

@Composable
private fun MobileTxCard(tx: MobileTransaction, onClick: () -> Unit) {
    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        modifier = Modifier.fillMaxWidth().clickable { onClick() }
    ) {
        Row(
            modifier = Modifier.padding(12.dp).fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(38.dp)
                    .background(
                        when (tx.type) {
                            "Sales" -> Color(0xFFDCFCE7)
                            "Purchase" -> Color(0xFFEFF6FF)
                            else -> Color(0xFFFFEDD5)
                        },
                        CircleShape
                    ),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = when (tx.type) {
                        "Sales" -> Icons.Default.Description
                        "Purchase" -> Icons.Default.ShoppingCart
                        else -> Icons.Default.TrendingDown
                    },
                    contentDescription = null,
                    tint = when (tx.type) {
                        "Sales" -> Color(0xFF16A34A)
                        "Purchase" -> Color(0xFF2563EB)
                        else -> Color(0xFFEA580C)
                    },
                    modifier = Modifier.size(18.dp)
                )
            }

            Column(modifier = Modifier.weight(1f)) {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(tx.docNumber, fontSize = 12.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                    Text("• ${tx.date}", fontSize = 10.sp, color = Color.Gray)
                }
                Text(tx.partyName, fontSize = 11.sp, color = Color(0xFF475569), maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    "₹${(tx.amount + tx.taxAmount).toInt()}",
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Black,
                    color = if (tx.type == "Sales") Color(0xFF16A34A) else Color(0xFF0F172A)
                )
                Surface(
                    color = if (tx.status == "Paid") Color(0xFFDCFCE7) else Color(0xFFFEF3C7),
                    shape = RoundedCornerShape(4.dp)
                ) {
                    Text(
                        tx.status.uppercase(),
                        fontSize = 8.sp,
                        fontWeight = FontWeight.Black,
                        color = if (tx.status == "Paid") Color(0xFF166534) else Color(0xFFB45309),
                        modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp)
                    )
                }
            }
        }
    }
}

@Composable
private fun ReportTile(title: String, desc: String, icon: ImageVector, onExport: () -> Unit) {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        modifier = Modifier.fillMaxWidth().clickable { onExport() }
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
                Text(desc, fontSize = 10.5.sp, color = Color.Gray)
            }
            Icon(Icons.Default.Download, contentDescription = null, tint = Color(0xFF4F46E5), modifier = Modifier.size(20.dp))
        }
    }
}

@Composable
private fun EmptyStateBox(message: String) {
    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Icon(Icons.Default.FolderOpen, contentDescription = null, tint = Color.LightGray, modifier = Modifier.size(40.dp))
            Text(message, fontSize = 12.sp, color = Color.Gray, textAlign = TextAlign.Center)
        }
    }
}
