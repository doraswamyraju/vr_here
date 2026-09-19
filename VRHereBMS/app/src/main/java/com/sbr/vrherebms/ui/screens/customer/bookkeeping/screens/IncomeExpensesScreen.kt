package com.sbr.vrherebms.ui.screens.customer.bookkeeping.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.components.EmptyStateBox
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.components.MobileTxCard
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.models.MobileTransaction

fun LazyListScope.incomeExpensesScreen(
    filteredTx: List<MobileTransaction>,
    selectedMonth: String,
    onShowCreateExpenseDialog: () -> Unit,
    onPreviewInvoice: (MobileTransaction) -> Unit
) {
    item {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text("Operating Expenses", fontWeight = FontWeight.Black, fontSize = 15.sp, color = Color(0xFF0F172A))
                Text("Direct & Indirect cash outflows", fontSize = 11.sp, color = Color(0xFF64748B))
            }
            Button(
                onClick = onShowCreateExpenseDialog,
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
            MobileTxCard(tx, onClick = { onPreviewInvoice(tx) })
        }
    }
}
