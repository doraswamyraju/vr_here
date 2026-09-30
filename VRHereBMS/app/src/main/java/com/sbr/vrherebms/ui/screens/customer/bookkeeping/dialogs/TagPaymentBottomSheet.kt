package com.sbr.vrherebms.ui.screens.customer.bookkeeping.dialogs

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Link
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.BankTransactionDto
import com.sbr.vrherebms.data.model.TransactionDto
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.utils.IndianCurrencyFormatter

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TagPaymentBottomSheet(
    bankTransaction: BankTransactionDto,
    openInvoicesOrBills: List<TransactionDto>,
    onDismiss: () -> Unit,
    onTagSubmitted: (voucherId: String?, category: String?, notes: String?) -> Unit
) {
    val context = LocalContext.current
    val primaryIndigo = Color(0xFF4F46E5)
    val textDark = Color(0xFF0F172A)
    val textMuted = Color(0xFF64748B)

    val isCredit = bankTransaction.type.equals("CREDIT", ignoreCase = true)

    var taggingMode by remember { mutableStateOf("Voucher") } // "Voucher" or "Category"
    var selectedVoucherId by remember { mutableStateOf<String?>(null) }
    var selectedCategory by remember {
        mutableStateOf(if (isCredit) "Direct Business Income" else "Office Space Rent")
    }
    var notes by remember { mutableStateOf("") }

    val defaultCategories = if (isCredit) {
        listOf("Direct Business Income", "Client Advance", "Interest Income", "Capital Infusion", "Tax Refund", "Other Receipts")
    } else {
        listOf("Office Space Rent", "Salaries & Wages", "Electricity & Utilities", "Software Subscriptions", "Travel & Conveyance", "Legal & Professional", "Bank Charges", "Petty Cash / Misc")
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        containerColor = Color.White,
        shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 12.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "Tag Bank Transaction",
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Black,
                        color = textDark
                    )
                    Text(
                        text = "Reconcile ${bankTransaction.description.take(30)}...",
                        fontSize = 11.5.sp,
                        color = textMuted
                    )
                }

                IconButton(
                    onClick = onDismiss,
                    modifier = Modifier.background(Color(0xFFF1F5F9), CircleShape).size(32.dp)
                ) {
                    Icon(Icons.Default.Close, contentDescription = "Close", tint = textMuted, modifier = Modifier.size(16.dp))
                }
            }

            // Transaction Snippet Card
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = if (isCredit) Color(0xFFDCFCE7).copy(alpha = 0.5f) else Color(0xFFFEE2E2).copy(alpha = 0.5f),
                border = BorderStroke(1.dp, if (isCredit) Color(0xFF86EFAC) else Color(0xFFFCA5A5)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(14.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = if (isCredit) "CREDIT (Money In)" else "DEBIT (Money Out)",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Black,
                            color = if (isCredit) Color(0xFF16A34A) else Color(0xFFDC2626)
                        )
                        Text(
                            text = bankTransaction.date.take(10),
                            fontSize = 11.sp,
                            color = textMuted
                        )
                    }
                    Text(
                        text = IndianCurrencyFormatter.format(bankTransaction.amount),
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Black,
                        color = if (isCredit) Color(0xFF16A34A) else Color(0xFFDC2626)
                    )
                }
            }

            // Mode Toggle (Link to Voucher vs Direct Ledger Category)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = if (taggingMode == "Voucher") primaryIndigo else Color(0xFFF1F5F9),
                    modifier = Modifier.weight(1f).clickable { taggingMode = "Voucher" }
                ) {
                    Text(
                        text = if (isCredit) "Link Sales Invoice" else "Link Purchase Bill",
                        fontSize = 11.5.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (taggingMode == "Voucher") Color.White else textDark,
                        modifier = Modifier.padding(vertical = 10.dp),
                        textAlign = androidx.compose.ui.text.style.TextAlign.Center
                    )
                }

                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = if (taggingMode == "Category") primaryIndigo else Color(0xFFF1F5F9),
                    modifier = Modifier.weight(1f).clickable { taggingMode = "Category" }
                ) {
                    Text(
                        text = "Direct Category Head",
                        fontSize = 11.5.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (taggingMode == "Category") Color.White else textDark,
                        modifier = Modifier.padding(vertical = 10.dp),
                        textAlign = androidx.compose.ui.text.style.TextAlign.Center
                    )
                }
            }

            // Option 1: Open Vouchers List
            if (taggingMode == "Voucher") {
                Text(
                    text = if (isCredit) "Select Open Unpaid Invoice:" else "Select Open Unpaid Bill:",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = textDark
                )

                if (openInvoicesOrBills.isEmpty()) {
                    Text(
                        text = "No open vouchers found. You can tag as a Direct Category Head.",
                        fontSize = 12.sp,
                        color = textMuted
                    )
                } else {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        openInvoicesOrBills.take(5).forEach { v ->
                            val isSelected = selectedVoucherId == v.id
                            Surface(
                                shape = RoundedCornerShape(10.dp),
                                color = if (isSelected) Color(0xFFEEF2FF) else Color.White,
                                border = BorderStroke(1.dp, if (isSelected) primaryIndigo else Color(0xFFE2E8F0)),
                                modifier = Modifier.fillMaxWidth().clickable { selectedVoucherId = v.id }
                            ) {
                                Row(
                                    modifier = Modifier.padding(12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column {
                                        Text(v.docNumber, fontSize = 12.5.sp, fontWeight = FontWeight.Black, color = textDark)
                                        Text(v.partyName, fontSize = 11.sp, color = textMuted)
                                    }
                                    Text(
                                        text = IndianCurrencyFormatter.format(v.summary.totalAmount),
                                        fontSize = 13.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = primaryIndigo
                                    )
                                }
                            }
                        }
                    }
                }
            } else {
                // Option 2: Category Selector
                Text("Select Ledger Head:", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = textDark)
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    defaultCategories.forEach { cat ->
                        val isSel = selectedCategory == cat
                        Surface(
                            shape = RoundedCornerShape(8.dp),
                            color = if (isSel) primaryIndigo else Color(0xFFF8FAFC),
                            border = BorderStroke(1.dp, if (isSel) primaryIndigo else Color(0xFFE2E8F0)),
                            modifier = Modifier.fillMaxWidth().clickable { selectedCategory = cat }
                        ) {
                            Text(
                                text = cat,
                                fontSize = 12.sp,
                                fontWeight = if (isSel) FontWeight.Bold else FontWeight.Medium,
                                color = if (isSel) Color.White else textDark,
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)
                            )
                        }
                    }
                }
            }

            OutlinedTextField(
                value = notes,
                onValueChange = { notes = it },
                label = { Text("Reconciliation Note (Optional)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            // Submit Button
            Button(
                onClick = {
                    if (taggingMode == "Voucher" && selectedVoucherId == null && openInvoicesOrBills.isNotEmpty()) {
                        Toast.makeText(context, "Please select a voucher to link", Toast.LENGTH_SHORT).show()
                        return@Button
                    }
                    onTagSubmitted(
                        if (taggingMode == "Voucher") selectedVoucherId else null,
                        if (taggingMode == "Category") selectedCategory else null,
                        notes.ifBlank { null }
                    )
                },
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = primaryIndigo),
                modifier = Modifier.fillMaxWidth().height(48.dp)
            ) {
                Icon(Icons.Default.Link, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Confirm & Reconcile Payment", fontWeight = FontWeight.Bold, fontSize = 13.5.sp)
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}
