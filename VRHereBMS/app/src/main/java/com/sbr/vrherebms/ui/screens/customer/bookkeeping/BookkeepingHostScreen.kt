package com.sbr.vrherebms.ui.screens.customer.bookkeeping

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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
import androidx.compose.ui.window.Dialog
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.models.*
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.screens.*
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BookkeepingHostScreen(viewModel: CustomerDashboardViewModel) {
    val context = LocalContext.current
    var selectedSubTab by remember { mutableStateOf("Dashboard") }
    var selectedMonth by remember { mutableStateOf("Sep 2026") }
    var searchQuery by remember { mutableStateOf("") }

    val monthsList = listOf(
        "Apr 2026", "May 2026", "Jun 2026", "Jul 2026", "Aug 2026", "Sep 2026",
        "Oct 2026", "Nov 2026", "Dec 2026", "Jan 2027", "Feb 2027", "Mar 2027"
    )

    val subModules = listOf(
        Triple("Dashboard", Icons.Default.Dashboard, "Executive Dashboard"),
        Triple("Sales", Icons.Default.Description, "Sales Invoices"),
        Triple("Purchases", Icons.Default.ShoppingCart, "Purchase Bills"),
        Triple("Expenses", Icons.Default.TrendingDown, "Income & Expenses")
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
    var previewInvoice by remember { mutableStateOf<MobileTransaction?>(null) }

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
        // 1. Suite Header Banner & Date Filter
        item {
            Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text("Bookkeeping Executive Dashboard", fontSize = 18.sp, fontWeight = FontWeight.Black, color = textDark)
                    }
                }

                // Date Filter Bar
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = Color.White,
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)) {
                            Icon(Icons.Default.CalendarMonth, contentDescription = null, tint = primaryIndigo, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("FY 2026-27", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = textDark)
                        }
                    }

                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = Color.White,
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp)) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null, tint = textMuted, modifier = Modifier.size(16.dp).clickable { 
                                val idx = monthsList.indexOf(selectedMonth)
                                if (idx > 0) selectedMonth = monthsList[idx - 1]
                            })
                            Spacer(modifier = Modifier.width(12.dp))
                            Text(selectedMonth, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = primaryIndigo)
                            Spacer(modifier = Modifier.width(12.dp))
                            Icon(Icons.Default.ArrowForward, contentDescription = null, tint = textMuted, modifier = Modifier.size(16.dp).clickable {
                                val idx = monthsList.indexOf(selectedMonth)
                                if (idx < monthsList.size - 1) selectedMonth = monthsList[idx + 1]
                            })
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
                            modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Icon(
                                imageVector = icon,
                                contentDescription = null,
                                tint = if (isSelected) Color.White else primaryIndigo,
                                modifier = Modifier.size(16.dp)
                            )
                            Text(
                                text = label,
                                fontSize = 12.sp,
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
            "Dashboard" -> executiveDashboardScreen(
                filteredTx = filteredTx,
                bankAccounts = bankAccounts,
                selectedMonth = selectedMonth,
                onShowCreateSalesDialog = { showCreateSalesDialog = true },
                onPreviewInvoice = { previewInvoice = it },
                onImportStatement = { Toast.makeText(context, "Import statement feature", Toast.LENGTH_SHORT).show() }
            )
            "Sales" -> salesInvoicesScreen(
                filteredTx = filteredTx,
                selectedMonth = selectedMonth,
                onShowCreateSalesDialog = { showCreateSalesDialog = true },
                onPreviewInvoice = { previewInvoice = it }
            )
            "Purchases" -> purchaseBillsScreen(
                filteredTx = filteredTx,
                selectedMonth = selectedMonth,
                onShowCreatePurchaseDialog = { showCreatePurchaseDialog = true },
                onPreviewInvoice = { previewInvoice = it }
            )
            "Expenses" -> incomeExpensesScreen(
                filteredTx = filteredTx,
                selectedMonth = selectedMonth,
                onShowCreateExpenseDialog = { showCreateExpenseDialog = true },
                onPreviewInvoice = { previewInvoice = it }
            )
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
}
