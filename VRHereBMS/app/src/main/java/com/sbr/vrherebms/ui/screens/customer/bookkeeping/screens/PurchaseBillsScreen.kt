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
import androidx.compose.material.icons.filled.ShoppingCart
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

fun LazyListScope.purchaseBillsScreen(
    purchaseTransactions: List<TransactionDto>,
    selectedStatusFilter: String,
    searchQuery: String,
    onStatusFilterChange: (String) -> Unit,
    onSearchQueryChange: (String) -> Unit,
    onCreateBill: () -> Unit,
    onViewBill: (TransactionDto) -> Unit,
    onDeleteBill: (TransactionDto) -> Unit
) {
    val emeraldColor = Color(0xFF059669)
    val textDark = Color(0xFF0F172A)
    val textMuted = Color(0xFF64748B)

    val totalPurchases = purchaseTransactions.sumOf { it.summary.totalAmount }
    val totalItc = purchaseTransactions.sumOf { it.summary.totalCgst + it.summary.totalSgst + it.summary.totalIgst }

    // 1. KPI Summaries
    item {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            BookkeepingKPICard(
                title = "Total Inward Bills",
                value = IndianCurrencyFormatter.formatNoDecimals(totalPurchases),
                subtitle = "${purchaseTransactions.size} Recorded Bills",
                icon = Icons.Default.ShoppingCart,
                accentColor = emeraldColor,
                modifier = Modifier.weight(1f)
            )
            BookkeepingKPICard(
                title = "Total Eligible ITC",
                value = IndianCurrencyFormatter.formatNoDecimals(totalItc),
                subtitle = "Input Tax Credit Available",
                icon = Icons.Default.ShoppingCart,
                accentColor = Color(0xFF4F46E5),
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
                placeholder = { Text("Search bill / vendor...", fontSize = 12.sp) },
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
                onClick = onCreateBill,
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = emeraldColor),
                modifier = Modifier.height(48.dp)
            ) {
                Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(4.dp))
                Text("Record Bill", fontSize = 12.sp, fontWeight = FontWeight.Bold)
            }
        }
    }

    // 3. Status Filters Bar
    item {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            listOf("All", "Paid", "Pending").forEach { status ->
                val isSel = selectedStatusFilter.equals(status, ignoreCase = true)
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = if (isSel) emeraldColor else Color.White,
                    border = BorderStroke(1.dp, if (isSel) emeraldColor else Color(0xFFE2E8F0)),
                    modifier = Modifier.clickable { onStatusFilterChange(status) }
                ) {
                    Text(
                        text = status,
                        fontSize = 11.sp,
                        fontWeight = if (isSel) FontWeight.Black else FontWeight.Bold,
                        color = if (isSel) Color.White else textDark,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
                    )
                }
            }
        }
    }

    // 4. Bills List
    val filtered = purchaseTransactions.filter { tx ->
        val statusMatch = selectedStatusFilter.equals("All", ignoreCase = true) ||
            tx.paymentStatus.equals(selectedStatusFilter, ignoreCase = true)
        val searchMatch = searchQuery.isBlank() ||
            tx.docNumber.contains(searchQuery, ignoreCase = true) ||
            tx.partyName.contains(searchQuery, ignoreCase = true)
        statusMatch && searchMatch
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
                    Icon(Icons.Default.ShoppingCart, contentDescription = null, tint = textMuted, modifier = Modifier.size(32.dp))
                    Text("No Purchase Bills Found", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = textDark)
                    Text("Record supplier invoices to track payables and claim ITC.", fontSize = 11.sp, color = textMuted)
                }
            }
        }
    } else {
        items(filtered) { tx ->
            TransactionItemCard(
                transaction = tx,
                onView = { onViewBill(tx) },
                onDelete = { onDeleteBill(tx) }
            )
        }
    }
}
