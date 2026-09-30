package com.sbr.vrherebms.ui.screens.customer.bookkeeping.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.BankStatementDto
import com.sbr.vrherebms.data.model.TransactionDto
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.components.BookkeepingKPICard
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.components.TransactionItemCard
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.utils.IndianCurrencyFormatter

fun LazyListScope.executiveDashboardScreen(
    transactions: List<TransactionDto>,
    bankStatements: List<BankStatementDto>,
    selectedMonth: String,
    onNavigateTab: (String) -> Unit,
    onCreateSales: () -> Unit,
    onCreatePurchase: () -> Unit,
    onCreateExpense: () -> Unit,
    onViewTransaction: (TransactionDto) -> Unit
) {
    val primaryIndigo = Color(0xFF4F46E5)
    val textDark = Color(0xFF0F172A)
    val textMuted = Color(0xFF64748B)

    // Calculate metrics
    val salesTx = transactions.filter { it.transactionType == "Sales" }
    val purchaseTx = transactions.filter { it.transactionType == "Purchase" }
    val expenseTx = transactions.filter { it.transactionType == "Expense" }

    val totalTurnover = salesTx.sumOf { it.summary.totalAmount }
    val totalPurchases = purchaseTx.sumOf { it.summary.totalAmount }
    val totalExpenses = expenseTx.sumOf { it.summary.totalAmount }

    val outputGst = salesTx.sumOf { it.summary.totalCgst + it.summary.totalSgst + it.summary.totalIgst }
    val inputItc = purchaseTx.sumOf { it.summary.totalCgst + it.summary.totalSgst + it.summary.totalIgst }
    val netGstPayable = (outputGst - inputItc).coerceAtLeast(0.0)

    val allBankTransactions = bankStatements.flatMap { it.transactions }
    val latestBankBalance = allBankTransactions.lastOrNull()?.balance ?: 0.0

    // 1. Quick Action Launcher Buttons
    item {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = primaryIndigo,
                modifier = Modifier.weight(1f).clickable { onCreateSales() },
                shadowElevation = 1.dp
            ) {
                Row(
                    modifier = Modifier.padding(vertical = 10.dp),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.Add, contentDescription = null, tint = Color.White, modifier = Modifier.size(15.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("+ Sales Inv", fontSize = 11.5.sp, fontWeight = FontWeight.Bold, color = Color.White)
                }
            }

            Surface(
                shape = RoundedCornerShape(12.dp),
                color = Color(0xFF059669),
                modifier = Modifier.weight(1f).clickable { onCreatePurchase() },
                shadowElevation = 1.dp
            ) {
                Row(
                    modifier = Modifier.padding(vertical = 10.dp),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.Add, contentDescription = null, tint = Color.White, modifier = Modifier.size(15.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("+ Bill", fontSize = 11.5.sp, fontWeight = FontWeight.Bold, color = Color.White)
                }
            }

            Surface(
                shape = RoundedCornerShape(12.dp),
                color = Color(0xFFD97706),
                modifier = Modifier.weight(1f).clickable { onCreateExpense() },
                shadowElevation = 1.dp
            ) {
                Row(
                    modifier = Modifier.padding(vertical = 10.dp),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.Add, contentDescription = null, tint = Color.White, modifier = Modifier.size(15.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("+ Expense", fontSize = 11.5.sp, fontWeight = FontWeight.Bold, color = Color.White)
                }
            }
        }
    }

    // 2. Executive KPI Grid
    item {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                BookkeepingKPICard(
                    title = "Monthly Revenue",
                    value = IndianCurrencyFormatter.formatNoDecimals(totalTurnover),
                    subtitle = "${salesTx.size} Invoices in $selectedMonth",
                    icon = Icons.Default.TrendingUp,
                    accentColor = primaryIndigo,
                    modifier = Modifier.weight(1f)
                )
                BookkeepingKPICard(
                    title = "Net GST Liability",
                    value = IndianCurrencyFormatter.formatNoDecimals(netGstPayable),
                    subtitle = "Output: ₹${outputGst.toInt()} | ITC: ₹${inputItc.toInt()}",
                    icon = Icons.Default.AccountBalance,
                    accentColor = Color(0xFFEF4444),
                    modifier = Modifier.weight(1f)
                )
            }

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                BookkeepingKPICard(
                    title = "Total Inward Purchases",
                    value = IndianCurrencyFormatter.formatNoDecimals(totalPurchases),
                    subtitle = "${purchaseTx.size} Bills Logged",
                    icon = Icons.Default.ShoppingCart,
                    accentColor = Color(0xFF059669),
                    modifier = Modifier.weight(1f)
                )
                BookkeepingKPICard(
                    title = "Operational Expenses",
                    value = IndianCurrencyFormatter.formatNoDecimals(totalExpenses),
                    subtitle = "${expenseTx.size} Vouchers Logged",
                    icon = Icons.Default.TrendingDown,
                    accentColor = Color(0xFFD97706),
                    modifier = Modifier.weight(1f)
                )
            }
        }
    }

    // 3. Bank Account Snapshot
    item {
        Surface(
            shape = RoundedCornerShape(16.dp),
            color = Color(0xFF0F172A),
            modifier = Modifier.fillMaxWidth().clickable { onNavigateTab("Banking") }
        ) {
            Row(
                modifier = Modifier.padding(16.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Box(
                        modifier = Modifier.size(36.dp).background(Color(0xFF6366F1), RoundedCornerShape(10.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(Icons.Default.AccountBalance, contentDescription = null, tint = Color.White, modifier = Modifier.size(18.dp))
                    }
                    Column {
                        Text("Connected Bank Accounts", fontSize = 12.5.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        Text("${bankStatements.size} Bank Statement Files Uploaded", fontSize = 10.5.sp, color = Color(0xFF94A3B8))
                    }
                }
                Icon(Icons.Default.ChevronRight, contentDescription = null, tint = Color(0xFF94A3B8))
            }
        }
    }

    // 4. Recent Transactions Section Header
    item {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("Recent Transactions", fontSize = 14.sp, fontWeight = FontWeight.Black, color = textDark)
            Text(
                text = "View All",
                fontSize = 11.5.sp,
                fontWeight = FontWeight.Bold,
                color = primaryIndigo,
                modifier = Modifier.clickable { onNavigateTab("Sales") }
            )
        }
    }

    // Recent Transactions List
    if (transactions.isEmpty()) {
        item {
            Surface(
                shape = RoundedCornerShape(14.dp),
                color = Color.White,
                border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp)
            ) {
                Column(
                    modifier = Modifier.padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Icon(Icons.Default.Inbox, contentDescription = null, tint = textMuted, modifier = Modifier.size(32.dp))
                    Text("No transactions recorded for $selectedMonth", fontSize = 12.5.sp, fontWeight = FontWeight.Bold, color = textDark)
                    Text("Tap '+ Sales Inv' or '+ Bill' above to get started.", fontSize = 11.sp, color = textMuted)
                }
            }
        }
    } else {
        items(transactions.take(5)) { tx ->
            TransactionItemCard(
                transaction = tx,
                onView = { onViewTransaction(tx) }
            )
        }
    }
}
