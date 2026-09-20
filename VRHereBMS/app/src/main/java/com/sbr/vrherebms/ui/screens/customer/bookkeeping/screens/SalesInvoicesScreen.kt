package com.sbr.vrherebms.ui.screens.customer.bookkeeping.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Receipt
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.components.EmptyStateBox
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.components.MobileTxCard
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.models.MobileTransaction

fun LazyListScope.salesInvoicesScreen(
    filteredTx: List<MobileTransaction>,
    selectedMonth: String,
    onShowCreateSalesDialog: () -> Unit,
    onPreviewInvoice: (MobileTransaction) -> Unit
) {
    val salesList = filteredTx.filter { it.type == "Sales" }
    val totalBilled = salesList.sumOf { it.amount + it.taxAmount }
    val totalPaid = salesList.filter { it.status.equals("Paid", ignoreCase = true) }.sumOf { it.amount + it.taxAmount }
    val totalPending = salesList.filter { !it.status.equals("Paid", ignoreCase = true) }.sumOf { it.amount + it.taxAmount }

    item {
        Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
            // Header Row with New Invoice Button
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text("Sales Invoices & Billing", fontWeight = FontWeight.Black, fontSize = 16.sp, color = Color(0xFF0F172A))
                    Text("GST compliant outward tax invoices & estimates", fontSize = 11.sp, color = Color(0xFF64748B))
                }
                Button(
                    onClick = onShowCreateSalesDialog,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                    shape = RoundedCornerShape(10.dp),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                ) {
                    Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(15.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Create Invoice", fontSize = 11.5.sp, fontWeight = FontWeight.Bold)
                }
            }

            // Bookkeeping Financial Summary Cards (Web Parity)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                // Total Billed Card
                Surface(
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(14.dp),
                    color = Color(0xFFEEF2FF),
                    border = BorderStroke(1.dp, Color(0xFFC7D2FE))
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Text("TOTAL BILLED", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF4338CA))
                        Text("₹${String.format("%,.0f", totalBilled)}", fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color(0xFF312E81))
                    }
                }

                // Total Collected Card
                Surface(
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(14.dp),
                    color = Color(0xFFECFDF5),
                    border = BorderStroke(1.dp, Color(0xFFA7F3D0))
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Text("COLLECTED", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF047857))
                        Text("₹${String.format("%,.0f", totalPaid)}", fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color(0xFF065F46))
                    }
                }

                // Outstanding Card
                Surface(
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(14.dp),
                    color = Color(0xFFFEF2F2),
                    border = BorderStroke(1.dp, Color(0xFFFECACA))
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Text("OUTSTANDING", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFFDC2626))
                        Text("₹${String.format("%,.0f", totalPending)}", fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color(0xFF991B1B))
                    }
                }
            }
        }
    }

    if (salesList.isEmpty()) {
        item { EmptyStateBox("No sales invoices found for $selectedMonth") }
    } else {
        items(salesList) { tx ->
            MobileTxCard(tx, onClick = { onPreviewInvoice(tx) })
        }
    }
}
