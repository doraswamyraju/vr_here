package com.sbr.vrherebms.ui.screens.customer.bookkeeping.screens

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
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
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.components.FinanceBox
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.components.MobileTxCard
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.models.MobileBankStatement
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.models.MobileTransaction

fun LazyListScope.executiveDashboardScreen(
    filteredTx: List<MobileTransaction>,
    bankAccounts: List<MobileBankStatement>,
    selectedMonth: String,
    onShowCreateSalesDialog: () -> Unit,
    onPreviewInvoice: (MobileTransaction) -> Unit,
    onImportStatement: () -> Unit
) {
    val totalSales = filteredTx.filter { it.type == "Sales" }.sumOf { it.amount + it.taxAmount }
    val totalPurchases = filteredTx.filter { it.type == "Purchase" }.sumOf { it.amount + it.taxAmount }
    val totalExpenses = filteredTx.filter { it.type == "Expense" }.sumOf { it.amount }
    
    item {
        Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
            // Hero Command Center Card (Dark Theme)
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A)),
                elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    Surface(
                        color = Color(0xFF1E293B),
                        shape = RoundedCornerShape(6.dp)
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)) {
                            Icon(Icons.Default.AutoAwesome, contentDescription = null, tint = Color(0xFF93C5FD), modifier = Modifier.size(12.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Real-Time Accounting & AaaS Command Center", color = Color(0xFF93C5FD), fontSize = 10.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                    
                    Text("Business Ledger & Bookkeeping", fontSize = 22.sp, fontWeight = FontWeight.Black, color = Color.White)
                    Text("Comprehensive financial visibility for $selectedMonth. Track receivables, vendor payables, GST liability, and bank reconciliation.", fontSize = 12.sp, color = Color(0xFF94A3B8), lineHeight = 18.sp)
                    
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Button(
                            onClick = onShowCreateSalesDialog,
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.weight(1f).height(44.dp)
                        ) {
                            Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("NEW INVOICE", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                        }
                        OutlinedButton(
                            onClick = onImportStatement,
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
                            border = BorderStroke(1.dp, Color(0xFF334155)),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.weight(1f).height(44.dp)
                        ) {
                            Icon(Icons.Default.UploadFile, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("IMPORT STATEMENT", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }

            // 4 Core Financial KPI Tiles
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                val totalPendingColl = filteredTx.filter { it.type == "Sales" && it.status != "Paid" }.sumOf { it.amount + it.taxAmount }
                FinanceBox(title = "TOTAL RECEIVABLES", value = "₹${totalSales.toInt()}", icon = Icons.Default.ArrowDownward, iconColor = Color(0xFF16A34A), indicatorText = "Pending Collection: ₹${totalPendingColl.toInt()}", indicatorColor = Color(0xFFDC2626), modifier = Modifier.weight(1f))
                
                val totalPendingPay = filteredTx.filter { it.type == "Purchase" && it.status != "Paid" }.sumOf { it.amount + it.taxAmount }
                FinanceBox(title = "VENDOR PAYABLES", value = "₹${totalPurchases.toInt()}", icon = Icons.Default.ArrowUpward, iconColor = Color(0xFFE11D48), indicatorText = "Pending Payment: ₹${totalPendingPay.toInt()}", indicatorColor = Color(0xFFDC2626), modifier = Modifier.weight(1f))
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                val outputGst = filteredTx.filter { it.type == "Sales" }.sumOf { it.taxAmount }
                val inputItc = filteredTx.filter { it.type == "Purchase" }.sumOf { it.taxAmount }
                val netGstPayable = maxOf(0.0, outputGst - inputItc)

                FinanceBox(title = "BANK STATEMENT ACTIVITY", value = "${bankAccounts.size} Txns", icon = Icons.Default.AccountBalance, iconColor = Color(0xFF4F46E5), indicatorText = "+30 In  -30 Out", indicatorColor = Color(0xFF16A34A), modifier = Modifier.weight(1f))
                FinanceBox(title = "NET GST LIABILITY (3B)", value = "₹${netGstPayable.toInt()}", icon = Icons.Default.Shield, iconColor = Color(0xFFD97706), indicatorText = "Output GST: ₹${outputGst.toInt()}", indicatorColor = Color(0xFF0F172A), modifier = Modifier.weight(1f))
            }

            // Action Tables Grid: Pending Invoices vs Pending Vendor Bills
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Pending Sales Invoices", fontWeight = FontWeight.Black, fontSize = 13.sp, color = Color(0xFF0F172A))
            }
        }
    }

    val pendingSales = filteredTx.filter { it.type == "Sales" && it.status != "Paid" }
    items(pendingSales.take(5)) { tx ->
        MobileTxCard(tx, onClick = { onPreviewInvoice(tx) })
    }
    
    item {
        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("Pending Purchase Bills", fontWeight = FontWeight.Black, fontSize = 13.sp, color = Color(0xFF0F172A))
        }
    }
    
    val pendingPurchases = filteredTx.filter { it.type == "Purchase" && it.status != "Paid" }
    items(pendingPurchases.take(5)) { tx ->
        MobileTxCard(tx, onClick = { onPreviewInvoice(tx) })
    }
}
