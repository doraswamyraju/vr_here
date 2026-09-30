package com.sbr.vrherebms.ui.screens.customer.bookkeeping.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountBalance
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material3.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.BankStatementDto
import com.sbr.vrherebms.data.model.BankTransactionDto
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.components.BankTransactionCard
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.components.BookkeepingKPICard
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.utils.IndianCurrencyFormatter

fun LazyListScope.bankStatementsScreen(
    bankStatements: List<BankStatementDto>,
    selectedStatusFilter: String, // "All", "Unreconciled", "Tagged"
    onStatusFilterChange: (String) -> Unit,
    onUploadStatement: () -> Unit,
    onTagTransaction: (BankTransactionDto) -> Unit
) {
    val primaryIndigo = Color(0xFF4F46E5)
    val textDark = Color(0xFF0F172A)
    val textMuted = Color(0xFF64748B)

    val allTransactions = bankStatements.flatMap { it.transactions }
    val unreconciledCount = allTransactions.count { !it.reconciliationStatus.equals("TAGGED", ignoreCase = true) }
    val taggedCount = allTransactions.count { it.reconciliationStatus.equals("TAGGED", ignoreCase = true) }
    val latestBalance = allTransactions.lastOrNull()?.balance ?: 0.0

    // 1. KPI Summaries
    item {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            BookkeepingKPICard(
                title = "Total Bank Balance",
                value = IndianCurrencyFormatter.formatNoDecimals(latestBalance),
                subtitle = "${bankStatements.size} Connected Statements",
                icon = Icons.Default.AccountBalance,
                accentColor = primaryIndigo,
                modifier = Modifier.weight(1f)
            )
            BookkeepingKPICard(
                title = "Unreconciled Lines",
                value = "$unreconciledCount Entries",
                subtitle = "$taggedCount Tagged & Settled",
                icon = Icons.Default.CheckCircle,
                accentColor = if (unreconciledCount > 0) Color(0xFFD97706) else Color(0xFF16A34A),
                modifier = Modifier.weight(1f)
            )
        }
    }

    // 2. Action Bar
    item {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("Statement Ledger Lines", fontSize = 13.5.sp, fontWeight = FontWeight.Black, color = textDark)

            Button(
                onClick = onUploadStatement,
                shape = RoundedCornerShape(10.dp),
                colors = ButtonDefaults.buttonColors(containerColor = primaryIndigo),
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                modifier = Modifier.height(36.dp)
            ) {
                Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(15.dp))
                Spacer(modifier = Modifier.width(4.dp))
                Text("Upload Statement", fontSize = 11.5.sp, fontWeight = FontWeight.Bold)
            }
        }
    }

    // 3. Status Filter Chips
    item {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            listOf("All", "Unreconciled", "Tagged").forEach { s ->
                val isSel = selectedStatusFilter.equals(s, ignoreCase = true)
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = if (isSel) primaryIndigo else Color.White,
                    border = BorderStroke(1.dp, if (isSel) primaryIndigo else Color(0xFFE2E8F0)),
                    modifier = Modifier.clickable { onStatusFilterChange(s) }
                ) {
                    Text(
                        text = s,
                        fontSize = 11.sp,
                        fontWeight = if (isSel) FontWeight.Black else FontWeight.Bold,
                        color = if (isSel) Color.White else textDark,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
                    )
                }
            }
        }
    }

    // 4. Filtered Transactions List
    val filtered = allTransactions.filter { tx ->
        when (selectedStatusFilter.lowercase()) {
            "tagged" -> tx.reconciliationStatus.equals("TAGGED", ignoreCase = true)
            "unreconciled" -> !tx.reconciliationStatus.equals("TAGGED", ignoreCase = true)
            else -> true
        }
    }

    if (filtered.isEmpty()) {
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
                    Icon(Icons.Default.AccountBalance, contentDescription = null, tint = textMuted, modifier = Modifier.size(32.dp))
                    Text("No Bank Statement Transactions", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = textDark)
                    Text("Upload your bank statement Excel/PDF to reconcile payments.", fontSize = 11.sp, color = textMuted)
                }
            }
        }
    } else {
        items(filtered) { tx ->
            BankTransactionCard(
                transaction = tx,
                onTagClick = { onTagTransaction(tx) }
            )
        }
    }
}
