package com.sbr.vrherebms.ui.screens.customer.bookkeeping.dialogs

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.sbr.vrherebms.data.model.CompanyDetailsDto
import com.sbr.vrherebms.data.model.TransactionDto
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.utils.IndianCurrencyFormatter
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.utils.InvoicePdfGenerator

@Composable
fun GSTInvoicePreviewDialog(
    transaction: TransactionDto,
    companyDetails: CompanyDetailsDto?,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val primaryIndigo = Color(0xFF4F46E5)
    val textDark = Color(0xFF0F172A)
    val textMuted = Color(0xFF64748B)

    val isSales = transaction.transactionType.equals("Sales", ignoreCase = true)
    val isPurchase = transaction.transactionType.equals("Purchase", ignoreCase = true)
    val isIncome = transaction.transactionType.equals("Income", ignoreCase = true)
    val isExpense = transaction.transactionType.equals("Expense", ignoreCase = true)

    val docTitle = when {
        isIncome -> "RECEIPT VOUCHER"
        isExpense -> "PAYMENT VOUCHER"
        isPurchase -> "PURCHASE INVOICE"
        else -> "TAX INVOICE"
    }

    val copyType = transaction.copyType.ifBlank { "Original for Recipient" }

    val supplierName = if (isSales || isIncome || isExpense) {
        companyDetails?.companyName?.ifBlank { null } ?: "VR HERE Business Solutions"
    } else {
        transaction.partyName
    }

    val supplierGstin = if (isSales || isIncome || isExpense) companyDetails?.gstin ?: "" else transaction.partyGstin
    val supplierAddress = if (isSales || isIncome || isExpense) companyDetails?.address ?: "Tirupati, Andhra Pradesh" else transaction.partyAddress
    val supplierState = if (isSales || isIncome || isExpense) companyDetails?.state ?: "Andhra Pradesh" else transaction.placeOfSupply
    val supplierPhone = if (isSales || isIncome || isExpense) companyDetails?.phone ?: "" else transaction.partyPhone

    val billToName = if (isSales) transaction.partyName else companyDetails?.companyName ?: "VR HERE Business Solutions"
    val billToGstin = if (isSales) transaction.partyGstin else companyDetails?.gstin ?: ""
    val billToAddress = if (isSales) transaction.partyAddress else companyDetails?.address ?: ""
    val billToState = if (isSales) transaction.partyState.ifBlank { transaction.placeOfSupply } else companyDetails?.state ?: ""

    val totalAmount = transaction.summary.totalAmount.takeIf { it > 0 }
        ?: transaction.items.sumOf { it.total }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 12.dp, vertical = 20.dp),
            shape = RoundedCornerShape(20.dp),
            color = Color.White,
            shadowElevation = 8.dp
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(14.dp)
            ) {
                // Top Action Toolbar
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        IconButton(
                            onClick = onDismiss,
                            modifier = Modifier.size(34.dp).background(Color(0xFFF1F5F9), RoundedCornerShape(8.dp))
                        ) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = textDark, modifier = Modifier.size(18.dp))
                        }
                        Column {
                            Text(docTitle, fontSize = 15.sp, fontWeight = FontWeight.Black, color = textDark)
                            Text(transaction.docNumber, fontSize = 11.5.sp, color = primaryIndigo, fontWeight = FontWeight.Bold)
                        }
                    }

                    // Share to WhatsApp PDF & Download PDF Buttons
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Button(
                            onClick = {
                                InvoicePdfGenerator.sharePdf(context, transaction, companyDetails, targetWhatsApp = true)
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF22C55E)),
                            shape = RoundedCornerShape(8.dp),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp),
                            modifier = Modifier.height(34.dp)
                        ) {
                            Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("WhatsApp PDF", fontSize = 10.5.sp, fontWeight = FontWeight.Bold)
                        }

                        Button(
                            onClick = {
                                InvoicePdfGenerator.downloadAndOpenPdf(context, transaction, companyDetails)
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = primaryIndigo),
                            shape = RoundedCornerShape(8.dp),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp),
                            modifier = Modifier.height(34.dp)
                        ) {
                            Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Download PDF", fontSize = 10.5.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }

                HorizontalDivider(color = Color(0xFFF1F5F9), modifier = Modifier.padding(vertical = 10.dp))

                // Scrollable Invoice Sheet Content strictly matching Web
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    // 1. Copy Indicator
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                        Surface(
                            shape = RoundedCornerShape(4.dp),
                            color = Color(0xFFF1F5F9),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                        ) {
                            Text(
                                text = "COPY: ${copyType.uppercase()}",
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFF64748B),
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                            )
                        }
                    }

                    // 2. Main Header Box (Supplier info & Doc metadata)
                    Surface(
                        shape = RoundedCornerShape(topStart = 10.dp, topEnd = 10.dp),
                        color = Color(0xFFF8FAFC),
                        border = BorderStroke(1.5.dp, Color(0xFF0F172A)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column(modifier = Modifier.weight(1.2f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text(supplierName, fontSize = 14.sp, fontWeight = FontWeight.Black, color = textDark)
                                Text(supplierAddress, fontSize = 10.5.sp, color = Color(0xFF475569))
                                if (supplierGstin.isNotBlank()) {
                                    Text("GSTIN: $supplierGstin | State: $supplierState", fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = textDark)
                                }
                                if (supplierPhone.isNotBlank()) {
                                    Text("Phone: $supplierPhone", fontSize = 10.sp, color = textMuted)
                                }
                            }

                            Column(modifier = Modifier.weight(0.9f), horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Surface(
                                    shape = RoundedCornerShape(4.dp),
                                    color = Color(0xFF0F172A)
                                ) {
                                    Text(
                                        text = docTitle,
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Black,
                                        color = Color.White,
                                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                                    )
                                }
                                Text("No: ${transaction.docNumber}", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = textDark)
                                Text("Date: ${transaction.docDate.take(10)}", fontSize = 10.5.sp, color = textMuted)
                                Text("Place of Supply: ${transaction.placeOfSupply}", fontSize = 10.sp, color = primaryIndigo, fontWeight = FontWeight.SemiBold)
                            }
                        }
                    }

                    // 3. BILL TO & SHIP TO Boxes
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(BorderStroke(1.5.dp, Color(0xFF0F172A)))
                    ) {
                        // BILL TO
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .padding(10.dp),
                            verticalArrangement = Arrangement.spacedBy(2.dp)
                        ) {
                            Text("BILL TO", fontSize = 10.sp, fontWeight = FontWeight.Black, color = primaryIndigo)
                            Text(billToName, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = textDark)
                            if (billToAddress.isNotBlank()) {
                                Text(billToAddress, fontSize = 10.sp, color = Color(0xFF475569))
                            }
                            if (billToGstin.isNotBlank()) {
                                Text("GSTIN: $billToGstin", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = textDark)
                            }
                        }

                        // Divider
                        Box(
                            modifier = Modifier
                                .width(1.dp)
                                .fillMaxHeight()
                                .background(Color(0xFFCBD5E1))
                        )

                        // SHIP TO
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .padding(10.dp),
                            verticalArrangement = Arrangement.spacedBy(2.dp)
                        ) {
                            Text("SHIP TO (Consignee)", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF475569))
                            Text(billToName, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = textDark)
                            if (billToAddress.isNotBlank()) {
                                Text(billToAddress, fontSize = 10.sp, color = Color(0xFF475569))
                            }
                            if (billToGstin.isNotBlank()) {
                                Text("GSTIN: $billToGstin", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = textDark)
                            }
                        }
                    }

                    // 4. Compact 10-Column Items Table (Horizontal scroll for small mobile screens)
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(BorderStroke(1.5.dp, Color(0xFF0F172A)))
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(Color(0xFF0F172A))
                                .padding(horizontal = 8.dp, vertical = 6.dp),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text("PARTICULARS & LINE ITEMS", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color.White)
                            Text("TAXABLE", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color.White)
                        }

                        transaction.items.forEachIndexed { i, item ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(if (i % 2 == 0) Color.White else Color(0xFFF8FAFC))
                                    .padding(horizontal = 10.dp, vertical = 8.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
                                    Text("${i + 1}. ${item.description}", fontSize = 11.5.sp, fontWeight = FontWeight.Bold, color = textDark)
                                    Text(
                                        text = "Qty: ${item.qty} ${item.unit} @ ₹${item.rate.toInt()} | GST: ${item.gstRate.toInt()}% | HSN: ${item.hsnSac.ifBlank { "-" }}",
                                        fontSize = 10.sp,
                                        color = textMuted
                                    )
                                }
                                Text(
                                    text = IndianCurrencyFormatter.format(item.total),
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Black,
                                    color = textDark
                                )
                            }
                            if (i < transaction.items.size - 1) {
                                HorizontalDivider(color = Color(0xFFE2E8F0))
                            }
                        }
                    }

                    // 5. Summary & Tax Calculation Box
                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = Color(0xFF0F172A),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text("Taxable Subtotal", fontSize = 11.sp, color = Color(0xFF94A3B8))
                                Text(IndianCurrencyFormatter.format(transaction.summary.totalTaxableValue), fontSize = 11.5.sp, color = Color.White)
                            }
                            if (transaction.summary.totalCgst > 0) {
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("CGST", fontSize = 11.sp, color = Color(0xFF94A3B8))
                                    Text(IndianCurrencyFormatter.format(transaction.summary.totalCgst), fontSize = 11.5.sp, color = Color.White)
                                }
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("SGST", fontSize = 11.sp, color = Color(0xFF94A3B8))
                                    Text(IndianCurrencyFormatter.format(transaction.summary.totalSgst), fontSize = 11.5.sp, color = Color.White)
                                }
                            }
                            if (transaction.summary.totalIgst > 0) {
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("IGST", fontSize = 11.sp, color = Color(0xFF94A3B8))
                                    Text(IndianCurrencyFormatter.format(transaction.summary.totalIgst), fontSize = 11.5.sp, color = Color.White)
                                }
                            }
                            HorizontalDivider(color = Color.White.copy(alpha = 0.15f), modifier = Modifier.padding(vertical = 4.dp))
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text("GRAND TOTAL", fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color.White)
                                Text(IndianCurrencyFormatter.format(totalAmount), fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFF818CF8))
                            }
                        }
                    }

                    // 6. Amount in Words & Bank Info
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = Color(0xFFF8FAFC),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            val words = transaction.summary.amountInWords.ifBlank { IndianCurrencyFormatter.numberToWords(totalAmount) }
                            Text("Amount in Words: $words", fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = textDark)
                            val bank = companyDetails?.bankDetails
                            if (!bank?.accountNumber.isNullOrBlank()) {
                                Text("Bank: ${bank?.bankName} | A/C: ${bank?.accountNumber} | IFSC: ${bank?.ifscCode} | UPI: ${companyDetails?.upiId}", fontSize = 9.5.sp, color = textMuted)
                            }
                        }
                    }
                }
            }
        }
    }
}
