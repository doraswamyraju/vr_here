package com.sbr.vrherebms.ui.screens.customer.bookkeeping

import android.widget.Toast
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.*
import com.sbr.vrherebms.data.remote.VRHereAPI
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.components.BookkeepingDateFilterBar
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.dialogs.*
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.screens.*
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BookkeepingHostScreen(viewModel: CustomerDashboardViewModel) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val api = remember { VRHereAPI.getInstance(context) }

    var selectedSubTab by remember { mutableStateOf("Dashboard") }
    var selectedMonth by remember { mutableStateOf("All Months") }
    var searchQuery by remember { mutableStateOf("") }
    var selectedStatusFilter by remember { mutableStateOf("All") }

    val monthsList = listOf(
        "All Months", "Apr 2026", "May 2026", "Jun 2026", "Jul 2026", "Aug 2026", "Sep 2026",
        "Oct 2026", "Nov 2026", "Dec 2026", "Jan 2027", "Feb 2027", "Mar 2027"
    )

    val subModules = listOf(
        Triple("Dashboard", Icons.Default.Dashboard, "Executive Dashboard"),
        Triple("Sales", Icons.Default.Description, "Sales Invoices"),
        Triple("Purchases", Icons.Default.ShoppingCart, "Purchase Bills"),
        Triple("Expenses", Icons.Default.TrendingDown, "Income & Expenses"),
        Triple("Banking", Icons.Default.AccountBalance, "Bank Statements"),
        Triple("Parties", Icons.Default.Apartment, "Customers & Vendors"),
        Triple("Reports", Icons.Default.BarChart, "Reports & P&L")
    )

    // Master Live Datasets from Server
    var transactions by remember { mutableStateOf<List<TransactionDto>>(emptyList()) }
    var parties by remember { mutableStateOf<List<PartyDto>>(emptyList()) }
    var bankStatements by remember { mutableStateOf<List<BankStatementDto>>(emptyList()) }
    var companyDetails by remember { mutableStateOf<CompanyDetailsDto?>(null) }
    var isLoading by remember { mutableStateOf(false) }

    // Dialogs & Sheets State
    var transactionFormType by remember { mutableStateOf<String?>(null) } // "Sales", "Purchase", "Expense", "Income"
    var editingTransaction by remember { mutableStateOf<TransactionDto?>(null) }
    var previewInvoice by remember { mutableStateOf<TransactionDto?>(null) }
    var taggingBankTx by remember { mutableStateOf<BankTransactionDto?>(null) }
    var showPartyDialog by remember { mutableStateOf(false) }
    var editingParty by remember { mutableStateOf<PartyDto?>(null) }
    var showCompanySettingsDialog by remember { mutableStateOf(false) }

    // Fetch live data from backend
    fun reloadAccountingData(silent: Boolean = false) {
        if (!silent) isLoading = true
        scope.launch {
            try {
                // 1. Fetch Transactions
                val txRes = api.getAccountingTransactions()
                if (txRes.isSuccessful && txRes.body() != null) {
                    transactions = txRes.body()!!
                }

                // 2. Fetch Parties
                val partyRes = api.getAccountingParties()
                if (partyRes.isSuccessful && partyRes.body() != null) {
                    parties = partyRes.body()!!
                }

                // 3. Fetch Bank Statements
                val bankRes = api.getBankStatements()
                if (bankRes.isSuccessful && bankRes.body() != null) {
                    bankStatements = bankRes.body()!!
                }

                // 4. Fetch Company Profile
                val compRes = api.getCompanyDetails()
                if (compRes.isSuccessful && compRes.body() != null) {
                    companyDetails = compRes.body()!!
                }
            } catch (e: Exception) {
                android.util.Log.e("BookkeepingHost", "Error syncing accounting data", e)
                if (!silent) {
                    Toast.makeText(context, "Sync error: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
                }
            } finally {
                isLoading = false
            }
        }
    }

    LaunchedEffect(Unit) {
        reloadAccountingData()
    }

    // Helper to check if a transaction date matches the selected month
    fun isDateInSelectedMonth(docDateStr: String?, targetMonth: String): Boolean {
        if (targetMonth == "All Months" || targetMonth.startsWith("All", ignoreCase = true)) return true
        if (docDateStr.isNullOrBlank()) return false
        try {
            val cleanDate = docDateStr.take(10) // "YYYY-MM-DD"
            val parts = cleanDate.split("-")
            if (parts.size >= 2) {
                val year = parts[0]
                val monthNum = parts[1].toIntOrNull() ?: return false
                val monthAbbr = when (monthNum) {
                    1 -> "Jan"; 2 -> "Feb"; 3 -> "Mar"; 4 -> "Apr"; 5 -> "May"; 6 -> "Jun"
                    7 -> "Jul"; 8 -> "Aug"; 9 -> "Sep"; 10 -> "Oct"; 11 -> "Nov"; 12 -> "Dec"
                    else -> ""
                }
                return targetMonth.contains(monthAbbr, ignoreCase = true) && targetMonth.contains(year)
            }
        } catch (e: Exception) {
            // Fallback
        }
        return true
    }

    // Filter transactions by selected month
    val filteredTransactions = remember(transactions, selectedMonth) {
        transactions.filter { isDateInSelectedMonth(it.docDate, selectedMonth) }
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
        // 1. Suite Header & Company Settings Trigger
        item {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "Bookkeeping & AaaS",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Black,
                            color = textDark
                        )
                        Text(
                            text = "Live GST Invoicing, Bills & Banking",
                            fontSize = 11.5.sp,
                            color = textMuted
                        )
                    }

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        // Refresh Button
                        IconButton(
                            onClick = { reloadAccountingData(silent = false) },
                            modifier = Modifier
                                .size(36.dp)
                                .background(Color.White, CircleShape)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Refresh,
                                contentDescription = "Refresh",
                                tint = primaryIndigo,
                                modifier = Modifier.size(18.dp)
                            )
                        }

                        // Company Settings Button
                        IconButton(
                            onClick = { showCompanySettingsDialog = true },
                            modifier = Modifier
                                .size(36.dp)
                                .background(Color.White, CircleShape)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Settings,
                                contentDescription = "Settings",
                                tint = primaryIndigo,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }
                }

                // Date & FY Filter Bar
                BookkeepingDateFilterBar(
                    financialYear = "FY 2026-27",
                    selectedMonth = selectedMonth,
                    monthsList = monthsList,
                    onMonthChange = { selectedMonth = it }
                )
            }
        }

        // 2. Sub-Modules Navigation Tabs Carousel
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
                        shadowElevation = if (isSelected) 3.dp else 0.5.dp,
                        modifier = Modifier.clickable {
                            selectedSubTab = id
                            searchQuery = ""
                            selectedStatusFilter = "All"
                        }
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

        // Loading Indicator Bar
        if (isLoading) {
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        color = primaryIndigo,
                        strokeWidth = 2.dp
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Syncing live database...",
                        fontSize = 11.5.sp,
                        color = textMuted,
                        fontWeight = FontWeight.Medium
                    )
                }
            }
        }

        // 3. Sub-Module Content Areas
        when (selectedSubTab) {
            "Dashboard" -> executiveDashboardScreen(
                transactions = filteredTransactions,
                bankStatements = bankStatements,
                selectedMonth = selectedMonth,
                onNavigateTab = { selectedSubTab = it },
                onCreateSales = {
                    editingTransaction = null
                    transactionFormType = "Sales"
                },
                onCreatePurchase = {
                    editingTransaction = null
                    transactionFormType = "Purchase"
                },
                onCreateExpense = {
                    editingTransaction = null
                    transactionFormType = "Expense"
                },
                onViewTransaction = { previewInvoice = it }
            )

            "Sales" -> salesInvoicesScreen(
                salesTransactions = filteredTransactions.filter { it.transactionType == "Sales" },
                selectedStatusFilter = selectedStatusFilter,
                searchQuery = searchQuery,
                onStatusFilterChange = { selectedStatusFilter = it },
                onSearchQueryChange = { searchQuery = it },
                onCreateInvoice = {
                    editingTransaction = null
                    transactionFormType = "Sales"
                },
                onViewInvoice = { previewInvoice = it },
                onDeleteInvoice = { tx ->
                    scope.launch {
                        try {
                            val res = api.deleteAccountingTransaction(tx.id)
                            if (res.isSuccessful) {
                                Toast.makeText(context, "Invoice deleted", Toast.LENGTH_SHORT).show()
                                reloadAccountingData(silent = true)
                            }
                        } catch (e: Exception) {
                            Toast.makeText(context, "Failed to delete: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            )

            "Purchases" -> purchaseBillsScreen(
                purchaseTransactions = filteredTransactions.filter { it.transactionType == "Purchase" },
                selectedStatusFilter = selectedStatusFilter,
                searchQuery = searchQuery,
                onStatusFilterChange = { selectedStatusFilter = it },
                onSearchQueryChange = { searchQuery = it },
                onCreateBill = {
                    editingTransaction = null
                    transactionFormType = "Purchase"
                },
                onViewBill = { previewInvoice = it },
                onDeleteBill = { tx ->
                    scope.launch {
                        try {
                            val res = api.deleteAccountingTransaction(tx.id)
                            if (res.isSuccessful) {
                                Toast.makeText(context, "Purchase bill deleted", Toast.LENGTH_SHORT).show()
                                reloadAccountingData(silent = true)
                            }
                        } catch (e: Exception) {
                            Toast.makeText(context, "Failed to delete: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            )

            "Expenses" -> incomeExpensesScreen(
                expenseTransactions = filteredTransactions.filter { it.transactionType == "Expense" || it.transactionType == "Income" },
                selectedTypeFilter = selectedStatusFilter,
                searchQuery = searchQuery,
                onTypeFilterChange = { selectedStatusFilter = it },
                onSearchQueryChange = { searchQuery = it },
                onCreateExpense = {
                    editingTransaction = null
                    transactionFormType = "Expense"
                },
                onViewExpense = { previewInvoice = it },
                onDeleteExpense = { tx ->
                    scope.launch {
                        try {
                            val res = api.deleteAccountingTransaction(tx.id)
                            if (res.isSuccessful) {
                                Toast.makeText(context, "Expense voucher deleted", Toast.LENGTH_SHORT).show()
                                reloadAccountingData(silent = true)
                            }
                        } catch (e: Exception) {
                            Toast.makeText(context, "Failed to delete: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            )

            "Banking" -> bankStatementsScreen(
                bankStatements = bankStatements,
                selectedStatusFilter = selectedStatusFilter,
                onStatusFilterChange = { selectedStatusFilter = it },
                onUploadStatement = {
                    Toast.makeText(context, "Upload Excel / PDF bank statement", Toast.LENGTH_SHORT).show()
                },
                onTagTransaction = { tx ->
                    taggingBankTx = tx
                }
            )

            "Parties" -> partiesScreen(
                parties = parties,
                selectedTypeFilter = selectedStatusFilter,
                searchQuery = searchQuery,
                onTypeFilterChange = { selectedStatusFilter = it },
                onSearchQueryChange = { searchQuery = it },
                onAddParty = {
                    editingParty = null
                    showPartyDialog = true
                },
                onEditParty = { p ->
                    editingParty = p
                    showPartyDialog = true
                },
                onDeleteParty = { p ->
                    scope.launch {
                        try {
                            val res = api.deleteAccountingParty(p.id)
                            if (res.isSuccessful) {
                                Toast.makeText(context, "Party deleted", Toast.LENGTH_SHORT).show()
                                reloadAccountingData(silent = true)
                            }
                        } catch (e: Exception) {
                            Toast.makeText(context, "Failed to delete: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            )

            "Reports" -> reportsScreen(
                transactions = filteredTransactions,
                selectedMonth = selectedMonth
            )
        }
    }

    // --- BOTTOM SHEETS & MODALS ---

    // 1. Transaction Form Sheet (Sales, Purchase, Expense, Income)
    if (transactionFormType != null) {
        val formType = transactionFormType!!
        TransactionFormBottomSheet(
            transactionType = formType,
            existingTransaction = editingTransaction,
            parties = parties,
            onDismiss = {
                transactionFormType = null
                editingTransaction = null
            },
            onSubmit = { payload ->
                scope.launch {
                    try {
                        val res = if (editingTransaction != null && editingTransaction!!.id.isNotBlank()) {
                            api.updateAccountingTransaction(editingTransaction!!.id, payload)
                        } else {
                            api.createAccountingTransaction(payload)
                        }

                        if (res.isSuccessful) {
                            Toast.makeText(context, "$formType recorded successfully!", Toast.LENGTH_SHORT).show()
                            transactionFormType = null
                            editingTransaction = null
                            reloadAccountingData(silent = true)
                        } else {
                            Toast.makeText(context, "Failed to save $formType: ${res.message()}", Toast.LENGTH_LONG).show()
                        }
                    } catch (e: Exception) {
                        Toast.makeText(context, "Connection error: ${e.localizedMessage}", Toast.LENGTH_LONG).show()
                    }
                }
            }
        )
    }

    // 2. Tag Payment Bottom Sheet (1-Click Manual Bank Reconciliation)
    if (taggingBankTx != null) {
        val bankTx = taggingBankTx!!
        val isCredit = bankTx.type.equals("CREDIT", ignoreCase = true)
        val openVouchers = transactions.filter {
            if (isCredit) it.transactionType == "Sales" && !it.paymentStatus.equals("Paid", ignoreCase = true)
            else it.transactionType == "Purchase" && !it.paymentStatus.equals("Paid", ignoreCase = true)
        }

        TagPaymentBottomSheet(
            bankTransaction = bankTx,
            openInvoicesOrBills = openVouchers,
            onDismiss = { taggingBankTx = null },
            onTagSubmitted = { voucherId, category, notes ->
                scope.launch {
                    try {
                        val statement = bankStatements.firstOrNull { it.transactions.any { t -> t.id == bankTx.id } }
                        if (statement != null) {
                            val req = TagBankTransactionRequest(
                                transactionId = bankTx.id,
                                voucherId = voucherId,
                                category = category,
                                notes = notes
                            )
                            val res = api.tagBankTransaction(statement.id, req)
                            if (res.isSuccessful) {
                                Toast.makeText(context, "Payment tagged & reconciled!", Toast.LENGTH_SHORT).show()
                                taggingBankTx = null
                                reloadAccountingData(silent = true)
                            } else {
                                Toast.makeText(context, "Tagging error: ${res.message()}", Toast.LENGTH_LONG).show()
                            }
                        }
                    } catch (e: Exception) {
                        Toast.makeText(context, "Connection error: ${e.localizedMessage}", Toast.LENGTH_LONG).show()
                    }
                }
            }
        )
    }

    // 3. Party Form Sheet (Add / Edit Customer & Vendor Master)
    if (showPartyDialog) {
        PartyFormBottomSheet(
            existingParty = editingParty,
            onDismiss = {
                showPartyDialog = false
                editingParty = null
            },
            onSubmit = { party ->
                scope.launch {
                    try {
                        val res = if (editingParty != null && editingParty!!.id.isNotBlank()) {
                            api.updateAccountingParty(editingParty!!.id, party)
                        } else {
                            api.createAccountingParty(party)
                        }

                        if (res.isSuccessful) {
                            Toast.makeText(context, "Party saved successfully!", Toast.LENGTH_SHORT).show()
                            showPartyDialog = false
                            editingParty = null
                            reloadAccountingData(silent = true)
                        } else {
                            Toast.makeText(context, "Failed to save party: ${res.message()}", Toast.LENGTH_LONG).show()
                        }
                    } catch (e: Exception) {
                        Toast.makeText(context, "Connection error: ${e.localizedMessage}", Toast.LENGTH_LONG).show()
                    }
                }
            }
        )
    }

    // 4. Company & Bank Settings Sheet
    if (showCompanySettingsDialog) {
        CompanySettingsBottomSheet(
            currentDetails = companyDetails,
            onDismiss = { showCompanySettingsDialog = false },
            onSubmit = { updated ->
                scope.launch {
                    try {
                        val res = api.updateCompanyDetails(updated)
                        if (res.isSuccessful) {
                            Toast.makeText(context, "Company settings updated!", Toast.LENGTH_SHORT).show()
                            companyDetails = res.body()
                            showCompanySettingsDialog = false
                        } else {
                            Toast.makeText(context, "Failed to update settings: ${res.message()}", Toast.LENGTH_LONG).show()
                        }
                    } catch (e: Exception) {
                        Toast.makeText(context, "Connection error: ${e.localizedMessage}", Toast.LENGTH_LONG).show()
                    }
                }
            }
        )
    }

    // 5. GST Invoice Preview & WhatsApp / PDF Dialog
    if (previewInvoice != null) {
        GSTInvoicePreviewDialog(
            transaction = previewInvoice!!,
            companyDetails = companyDetails,
            onDismiss = { previewInvoice = null }
        )
    }
}
