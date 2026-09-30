package com.sbr.vrherebms.ui.screens.customer.bookkeeping.dialogs

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
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
import com.sbr.vrherebms.data.model.CompanyDetailsDto
import com.sbr.vrherebms.data.model.TransactionDto
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.utils.IndianCurrencyFormatter

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

    val totalAmount = transaction.summary.totalAmount.takeIf { it > 0 }
        ?: transaction.items.sumOf { it.total }

    Dialog(onDismissRequest = onDismiss) {
        Card(
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.9f)
                .padding(4.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp)
            ) {
                // Header Row
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = if (transaction.transactionType == "Sales") "TAX INVOICE" else "${transaction.transactionType.uppercase()} VOUCHER",
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Black,
                            color = textDark
                        )
                        Text(
                            text = transaction.docNumber,
                            fontSize = 12.sp,
                            color = primaryIndigo,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = "Close", tint = textMuted)
                    }
                }

                HorizontalDivider(color = Color(0xFFF1F5F9), modifier = Modifier.padding(vertical = 8.dp))

                // Scrollable Invoice Sheet Content
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    // Company Supplier Block
                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = Color(0xFFF8FAFC),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text(
                                text = companyDetails?.companyName?.ifBlank { null } ?: "VR Here Business Solutions",
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Black,
                                color = textDark
                            )
                            if (!companyDetails?.gstin.isNullOrBlank()) {
                                Text("GSTIN: ${companyDetails?.gstin}", fontSize = 11.sp, color = textMuted, fontWeight = FontWeight.Bold)
                            }
                            if (!companyDetails?.address.isNullOrBlank()) {
                                Text(companyDetails?.address ?: "", fontSize = 10.5.sp, color = textMuted)
                            }
                        }
                    }

                    // Bill To Block
                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = Color(0xFFF8FAFC),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text(
                                text = "Billed To: ${transaction.partyName}",
                                fontSize = 12.5.sp,
                                fontWeight = FontWeight.Bold,
                                color = textDark
                            )
                            if (transaction.partyGstin.isNotBlank()) {
                                Text("GSTIN: ${transaction.partyGstin}", fontSize = 11.sp, color = textMuted)
                            }
                            if (transaction.partyAddress.isNotBlank()) {
                                Text(transaction.partyAddress, fontSize = 10.5.sp, color = textMuted)
                            }
                            Text("Place of Supply: ${transaction.placeOfSupply}", fontSize = 10.5.sp, color = primaryIndigo, fontWeight = FontWeight.SemiBold)
                        }
                    }

                    // Line Items Table Snippet
                    Text("Particulars", fontSize = 12.sp, fontWeight = FontWeight.Black, color = textDark)
                    transaction.items.forEachIndexed { i, item ->
                        Surface(
                            shape = RoundedCornerShape(8.dp),
                            color = Color.White,
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(
                                modifier = Modifier.padding(10.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(item.description, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = textDark)
                                    Text("Qty: ${item.qty} ${item.unit} @ ₹${item.rate.toInt()}", fontSize = 10.5.sp, color = textMuted)
                                }
                                Text(IndianCurrencyFormatter.format(item.total), fontSize = 12.5.sp, fontWeight = FontWeight.Black, color = textDark)
                            }
                        }
                    }

                    // Calculation breakdown
                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = Color(0xFF0F172A),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text("Taxable Value", fontSize = 11.5.sp, color = Color(0xFF94A3B8))
                                Text(IndianCurrencyFormatter.format(transaction.summary.totalTaxableValue), fontSize = 11.5.sp, color = Color.White)
                            }
                            if (transaction.summary.totalCgst > 0) {
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("CGST", fontSize = 11.5.sp, color = Color(0xFF94A3B8))
                                    Text(IndianCurrencyFormatter.format(transaction.summary.totalCgst), fontSize = 11.5.sp, color = Color.White)
                                }
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("SGST", fontSize = 11.5.sp, color = Color(0xFF94A3B8))
                                    Text(IndianCurrencyFormatter.format(transaction.summary.totalSgst), fontSize = 11.5.sp, color = Color.White)
                                }
                            }
                            if (transaction.summary.totalIgst > 0) {
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("IGST", fontSize = 11.5.sp, color = Color(0xFF94A3B8))
                                    Text(IndianCurrencyFormatter.format(transaction.summary.totalIgst), fontSize = 11.5.sp, color = Color.White)
                                }
                            }
                            HorizontalDivider(color = Color.White.copy(alpha = 0.15f), modifier = Modifier.padding(vertical = 4.dp))
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text("GRAND TOTAL", fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color.White)
                                Text(IndianCurrencyFormatter.format(totalAmount), fontSize = 15.sp, fontWeight = FontWeight.Black, color = Color(0xFF818CF8))
                            }
                        }
                    }

                    if (transaction.summary.amountInWords.isNotBlank()) {
                        Text(
                            text = "Amount in Words: ${transaction.summary.amountInWords}",
                            fontSize = 10.5.sp,
                            color = textMuted,
                            fontWeight = FontWeight.Medium
                        )
                    }

                    // Bank details & UPI
                    if (!companyDetails?.bankDetails?.accountNumber.isNullOrBlank()) {
                        Surface(
                            shape = RoundedCornerShape(8.dp),
                            color = Color(0xFFF1F5F9),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text("Bank Transfer Details:", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = textDark)
                                Text("Bank: ${companyDetails?.bankDetails?.bankName} | A/C: ${companyDetails?.bankDetails?.accountNumber}", fontSize = 10.5.sp, color = textMuted)
                                Text("IFSC: ${companyDetails?.bankDetails?.ifscCode} | UPI: ${companyDetails?.upiId}", fontSize = 10.5.sp, color = textMuted)
                            }
                        }
                    }
                }

                HorizontalDivider(color = Color(0xFFF1F5F9), modifier = Modifier.padding(vertical = 8.dp))

                // Action Buttons: WhatsApp Share & Download PDF
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = {
                            val msg = "Tax Invoice ${transaction.docNumber}\nBilled to: ${transaction.partyName}\nAmount: ${IndianCurrencyFormatter.format(totalAmount)}\nThank you for your business!"
                            val intent = Intent(Intent.ACTION_VIEW).apply {
                                data = Uri.parse("https://api.whatsapp.com/send?text=" + Uri.encode(msg))
                            }
                            try {
                                context.startActivity(intent)
                            } catch (e: Exception) {
                                Toast.makeText(context, "WhatsApp not installed", Toast.LENGTH_SHORT).show()
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF22C55E)),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.weight(1f).height(44.dp)
                    ) {
                        Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("WhatsApp", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }

                    Button(
                        onClick = {
                            Toast.makeText(context, "Generating PDF invoice for ${transaction.docNumber}...", Toast.LENGTH_SHORT).show()
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = primaryIndigo),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.weight(1.3f).height(44.dp)
                    ) {
                        Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Download PDF", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }
}
