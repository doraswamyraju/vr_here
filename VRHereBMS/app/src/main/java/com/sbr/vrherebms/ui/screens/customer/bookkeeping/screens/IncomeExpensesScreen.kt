package com.sbr.vrherebms.ui.screens.customer.bookkeeping.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.TrendingDown
import androidx.compose.material3.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.TransactionDto
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.components.BookkeepingKPICard
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.components.TransactionItemCard
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.utils.IndianCurrencyFormatter

fun LazyListScope.incomeExpensesScreen(
    expenseTransactions: List<TransactionDto>,
    selectedTypeFilter: String, // "All", "Expense", "Income"
    searchQuery: String,
    onTypeFilterChange: (String) -> Unit,
    onSearchQueryChange: (String) -> Unit,
    onCreateExpense: () -> Unit,
    onViewExpense: (TransactionDto) -> Unit,
    onDeleteExpense: (TransactionDto) -> Unit
) {
    val amberColor = Color(0xFFD97706)
    val textDark = Color(0xFF0F172A)
    val textMuted = Color(0xFF64748B)

    val totalExpenses = expenseTransactions.filter { it.transactionType == "Expense" }.sumOf { it.summary.totalAmount }
    val totalIncome = expenseTransactions.filter { it.transactionType == "Income" }.sumOf { it.summary.totalAmount }

    // 1. KPI Summaries
    item {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            BookkeepingKPICard(
                title = "Total Operational Expenses",
                value = IndianCurrencyFormatter.formatNoDecimals(totalExpenses),
                subtitle = "Rent, Salaries, Utilities, Petty Cash",
                icon = Icons.Default.TrendingDown,
                accentColor = amberColor,
                modifier = Modifier.weight(1f)
            )
            BookkeepingKPICard(
                title = "Other Income Receipts",
                value = IndianCurrencyFormatter.formatNoDecimals(totalIncome),
                subtitle = "Direct Income & Advances",
                icon = Icons.Default.TrendingDown,
                accentColor = Color(0xFF16A34A),
                modifier = Modifier.weight(1f)
            )
        }
    }

    // 2. Search & Create Button Bar
    item {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = searchQuery,
                onValueChange = onSearchQueryChange,
                placeholder = { Text("Search expense / category...", fontSize = 12.sp) },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = textMuted, modifier = Modifier.size(18.dp)) },
                modifier = Modifier.weight(1f).height(48.dp),
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    unfocusedContainerColor = Color.White,
                    focusedContainerColor = Color.White
                ),
                singleLine = true
            )

            Button(
                onClick = onCreateExpense,
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = amberColor),
                modifier = Modifier.height(48.dp)
            ) {
                Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(4.dp))
                Text("Log Expense", fontSize = 12.sp, fontWeight = FontWeight.Bold)
            }
        }
    }

    // 3. Type Filters Bar
    item {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            listOf("All", "Expense", "Income").forEach { t ->
                val isSel = selectedTypeFilter.equals(t, ignoreCase = true)
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = if (isSel) amberColor else Color.White,
                    border = BorderStroke(1.dp, if (isSel) amberColor else Color(0xFFE2E8F0)),
                    modifier = Modifier.clickable { onTypeFilterChange(t) }
                ) {
                    Text(
                        text = t,
                        fontSize = 11.sp,
                        fontWeight = if (isSel) FontWeight.Black else FontWeight.Bold,
                        color = if (isSel) Color.White else textDark,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
                    )
                }
            }
        }
    }

    // 4. Expense Vouchers List
    val filtered = expenseTransactions.filter { tx ->
        val typeMatch = selectedTypeFilter.equals("All", ignoreCase = true) ||
            tx.transactionType.equals(selectedTypeFilter, ignoreCase = true)
        val searchMatch = searchQuery.isBlank() ||
            tx.docNumber.contains(searchQuery, ignoreCase = true) ||
            tx.partyName.contains(searchQuery, ignoreCase = true) ||
            tx.items.any { it.description.contains(searchQuery, ignoreCase = true) }
        typeMatch && searchMatch
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
                    Icon(Icons.Default.TrendingDown, contentDescription = null, tint = textMuted, modifier = Modifier.size(32.dp))
                    Text("No Expense Vouchers Recorded", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = textDark)
                    Text("Log daily operational expenses, petty cash, and utilities.", fontSize = 11.sp, color = textMuted)
                }
            }
        }
    } else {
        items(filtered) { tx ->
            TransactionItemCard(
                transaction = tx,
                onView = { onViewExpense(tx) },
                onDelete = { onDeleteExpense(tx) }
            )
        }
    }
}
