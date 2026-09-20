package com.sbr.vrherebms.ui.screens.customer

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties

data class GSTInvoiceItemData(
    val description: String,
    val hsn: String = "998311",
    val qty: Int = 1,
    val rate: Double,
    val taxRate: Double = 18.0,
    val amount: Double
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GSTSalesInvoiceTemplateModal(
    invoiceNumber: String,
    invoiceDate: String,
    dueDate: String? = null,
    clientName: String,
    clientAddress: String = "Telangana, India",
    clientGstin: String = "N/A",
    clientEmail: String = "",
    clientPhone: String = "",
    items: List<GSTInvoiceItemData>,
    subtotal: Double,
    cgst: Double,
    sgst: Double,
    igst: Double = 0.0,
    totalAmount: Double,
    status: String = "COMPLETED",
    pdfUrl: String? = null,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val scrollState = rememberScrollState()

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier
                .fillMaxWidth(0.95f)
                .fillMaxHeight(0.92f),
            shape = RoundedCornerShape(20.dp),
            color = Color.White,
            shadowElevation = 8.dp
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp)
            ) {
                // Top Control Bar
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Surface(
                            shape = RoundedCornerShape(8.dp),
                            color = Color(0xFF0F172A)
                        ) {
                            Text("GST TAX INVOICE", color = Color.White, fontSize = 10.sp, fontWeight = FontWeight.Black, modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp))
                        }
                        Text("#$invoiceNumber", fontSize = 12.sp, fontWeight = FontWeight.Black, color = Color(0xFFDC2626))
                    }

                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = "Close", tint = Color(0xFF64748B))
                    }
                }

                HorizontalDivider(color = Color(0xFFE2E8F0), modifier = Modifier.padding(vertical = 8.dp))

                // Scrollable Printable Document Content
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .verticalScroll(scrollState)
                        .background(Color.White)
                        .padding(8.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    // 1. Company Header (VR HERE)
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(BorderStroke(1.dp, Color(0xFFE2E8F0)), RoundedCornerShape(12.dp))
                            .padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.Top
                    ) {
                        Column {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Surface(
                                    shape = RoundedCornerShape(8.dp),
                                    color = Color(0xFF0F172A)
                                ) {
                                    Text("VR", color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.Black, modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp))
                                }
                                Column {
                                    Text("VR HERE", fontSize = 18.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A), letterSpacing = (-0.5).sp)
                                    Text("BUSINESS SOLUTIONS", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFFDC2626), letterSpacing = 1.sp)
                                }
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            Text("📍 Hyderabad, Telangana, India", fontSize = 10.sp, color = Color(0xFF64748B), fontWeight = FontWeight.Medium)
                            Text("📞 +91 80085 30606", fontSize = 10.sp, color = Color(0xFF64748B), fontWeight = FontWeight.Medium)
                            Text("✉️ support@vrhere.in", fontSize = 10.sp, color = Color(0xFF64748B), fontWeight = FontWeight.Medium)
                            Text("GSTIN: 36AAAAA0000A1Z5", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                        }

                        Column(horizontalAlignment = Alignment.End) {
                            Text("TAX INVOICE", fontSize = 18.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                            Text("#$invoiceNumber", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF64748B))
                            Text("Date: $invoiceDate", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                            if (!dueDate.isNullOrEmpty()) {
                                Text("Due: $dueDate", fontSize = 9.sp, fontWeight = FontWeight.Bold, color = Color(0xFFDC2626))
                            }
                            Surface(
                                shape = RoundedCornerShape(6.dp),
                                color = if (status.equals("COMPLETED", ignoreCase = true) || status.equals("PAID", ignoreCase = true)) Color(0xFFD1FAE5) else Color(0xFFFEF3C7),
                                modifier = Modifier.padding(top = 6.dp)
                            ) {
                                Text(status.uppercase(), fontSize = 9.sp, fontWeight = FontWeight.Black, color = if (status.equals("COMPLETED", ignoreCase = true) || status.equals("PAID", ignoreCase = true)) Color(0xFF047857) else Color(0xFFB45309), modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                            }
                        }
                    }

                    // 2. Bill To & Supply Metadata Cards
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        // Bill To Card
                        Surface(
                            modifier = Modifier.weight(1.2f),
                            shape = RoundedCornerShape(12.dp),
                            color = Color(0xFFF8FAFC),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                        ) {
                            Column(modifier = Modifier.padding(10.dp)) {
                                Text("BILL TO:", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8), letterSpacing = 0.5.sp)
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(clientName.ifEmpty { "Valued Customer" }, fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                if (clientAddress.isNotEmpty()) {
                                    Text(clientAddress, fontSize = 10.sp, color = Color(0xFF475569))
                                }
                                Text("GSTIN: ${clientGstin.ifEmpty { "N/A" }}", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                if (clientEmail.isNotEmpty() || clientPhone.isNotEmpty()) {
                                    Text("${clientEmail.ifEmpty { clientPhone }}", fontSize = 9.sp, color = Color(0xFF64748B))
                                }
                            }
                        }

                        // Supply Info Card
                        Surface(
                            modifier = Modifier.weight(0.8f),
                            shape = RoundedCornerShape(12.dp),
                            color = Color(0xFFF1F5F9),
                            border = BorderStroke(1.dp, Color(0xFFCBD5E1))
                        ) {
                            Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("Place of Supply:", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B))
                                    Text("Telangana (36)", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                }
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("Reverse Charge:", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B))
                                    Text("No", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                }
                            }
                        }
                    }

                    // 3. Line Items Table
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column {
                            // Table Header
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(Color(0xFF0F172A))
                                    .padding(horizontal = 10.dp, vertical = 8.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("DESCRIPTION", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color.White, modifier = Modifier.weight(1.8f))
                                Text("HSN", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color.White, modifier = Modifier.weight(0.7f), textAlign = TextAlign.Center)
                                Text("QTY", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color.White, modifier = Modifier.weight(0.5f), textAlign = TextAlign.Center)
                                Text("RATE", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color.White, modifier = Modifier.weight(0.8f), textAlign = TextAlign.End)
                                Text("GST", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color.White, modifier = Modifier.weight(0.6f), textAlign = TextAlign.End)
                                Text("AMOUNT", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color.White, modifier = Modifier.weight(1f), textAlign = TextAlign.End)
                            }

                            // Table Rows
                            items.forEachIndexed { index, item ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .background(if (index % 2 == 0) Color.White else Color(0xFFF8FAFC))
                                        .padding(horizontal = 10.dp, vertical = 8.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(item.description, fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A), modifier = Modifier.weight(1.8f))
                                    Text(item.hsn, fontSize = 9.sp, color = Color(0xFF64748B), modifier = Modifier.weight(0.7f), textAlign = TextAlign.Center)
                                    Text("${item.qty}", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A), modifier = Modifier.weight(0.5f), textAlign = TextAlign.Center)
                                    Text("₹${item.rate.toInt()}", fontSize = 9.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A), modifier = Modifier.weight(0.8f), textAlign = TextAlign.End)
                                    Text("${item.taxRate.toInt()}%", fontSize = 9.sp, color = Color(0xFF64748B), modifier = Modifier.weight(0.6f), textAlign = TextAlign.End)
                                    Text("₹${item.amount.toInt()}", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A), modifier = Modifier.weight(1f), textAlign = TextAlign.End)
                                }
                                if (index < items.size - 1) {
                                    HorizontalDivider(color = Color(0xFFF1F5F9))
                                }
                            }
                        }
                    }

                    // 4. Financial Calculations Summary Box
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End
                    ) {
                        Surface(
                            modifier = Modifier.width(220.dp),
                            shape = RoundedCornerShape(12.dp),
                            color = Color(0xFFF8FAFC),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                        ) {
                            Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("Subtotal", fontSize = 10.sp, color = Color(0xFF64748B))
                                    Text("₹${String.format("%,.2f", subtotal)}", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                }
                                if (cgst > 0) {
                                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                        Text("CGST (9%)", fontSize = 9.sp, color = Color(0xFF64748B))
                                        Text("₹${String.format("%,.2f", cgst)}", fontSize = 9.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                    }
                                }
                                if (sgst > 0) {
                                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                        Text("SGST (9%)", fontSize = 9.sp, color = Color(0xFF64748B))
                                        Text("₹${String.format("%,.2f", sgst)}", fontSize = 9.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                    }
                                }
                                if (igst > 0) {
                                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                        Text("IGST", fontSize = 9.sp, color = Color(0xFF64748B))
                                        Text("₹${String.format("%,.2f", igst)}", fontSize = 9.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                    }
                                }
                                HorizontalDivider(color = Color(0xFF0F172A), modifier = Modifier.padding(vertical = 2.dp))
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("TOTAL", fontSize = 12.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                    Text("₹${String.format("%,.0f", totalAmount)}", fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color(0xFFDC2626))
                                }
                            }
                        }
                    }

                    // 5. Footer & Bank Details Section
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = Color(0xFFF1F5F9),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(10.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.Bottom
                        ) {
                            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text("BANK DETAILS:", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B), letterSpacing = 0.5.sp)
                                Text("Bank: HDFC BANK LTD", fontSize = 9.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                Text("A/c Name: VR HERE BUSINESS SOLUTIONS", fontSize = 9.sp, color = Color(0xFF334155))
                                Text("A/c No: XXXXXXXXXXXXXXXX", fontSize = 9.sp, color = Color(0xFF334155))
                                Text("IFSC: HDFC000XXXX • Branch: HYDERABAD", fontSize = 9.sp, color = Color(0xFF334155))
                            }

                            Column(horizontalAlignment = Alignment.End) {
                                Text("Authorized Signatory", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B))
                                Spacer(modifier = Modifier.height(14.dp))
                                HorizontalDivider(color = Color(0xFF0F172A), modifier = Modifier.width(100.dp))
                                Spacer(modifier = Modifier.height(2.dp))
                                Text("VR HERE BUSINESS SOLUTIONS", fontSize = 7.5.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                            }
                        }
                    }
                }

                // Bottom Action Button
                Button(
                    onClick = {
                        if (!pdfUrl.isNullOrEmpty()) {
                            try {
                                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(pdfUrl))
                                context.startActivity(intent)
                            } catch (e: Exception) {
                                Toast.makeText(context, "Opening PDF...", Toast.LENGTH_SHORT).show()
                            }
                        } else {
                            Toast.makeText(context, "Downloading PDF Invoice #$invoiceNumber...", Toast.LENGTH_SHORT).show()
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF0F172A)),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(46.dp)
                ) {
                    Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Download PDF Invoice", fontSize = 12.sp, fontWeight = FontWeight.Black)
                }
            }
        }
    }
}
