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

fun LazyListScope.purchaseBillsScreen(
    filteredTx: List<MobileTransaction>,
    selectedMonth: String,
    onShowCreatePurchaseDialog: () -> Unit,
    onPreviewInvoice: (MobileTransaction) -> Unit
) {
    item {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text("Purchase Bills", fontWeight = FontWeight.Black, fontSize = 15.sp, color = Color(0xFF0F172A))
                Text("Inward vendor bills & Input Tax Credit (ITC)", fontSize = 11.sp, color = Color(0xFF64748B))
            }
            Button(
                onClick = onShowCreatePurchaseDialog,
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
            MobileTxCard(tx, onClick = { onPreviewInvoice(tx) })
        }
    }
}
