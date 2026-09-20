package com.sbr.vrherebms.ui.screens.customer

import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.local.SessionManager
import com.sbr.vrherebms.data.model.OrderResponse
import com.sbr.vrherebms.data.model.PaymentResponse
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomerInvoicesTab(
    viewModel: CustomerDashboardViewModel,
    isEmbedded: Boolean = false
) {
    val context = LocalContext.current
    val sessionManager = remember { SessionManager(context) }
    val payments = viewModel.payments
    val orders = viewModel.orders

    val totalSpent = remember(payments) { payments.sumOf { it.amount } }

    // GST Invoice Modal View State
    var selectedInvoicePayment by remember { mutableStateOf<PaymentResponse?>(null) }
    var showInvoiceModal by remember { mutableStateOf(false) }

    // Payment Settlement Sheet State
    var selectedPaymentForCheckout by remember { mutableStateOf<PaymentResponse?>(null) }
    var showCheckoutSheet by remember { mutableStateOf(false) }

    if (isEmbedded) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            CustomerInvoicesContent(
                payments = payments,
                orders = orders,
                totalSpent = totalSpent,
                onSelectInvoice = {
                    selectedInvoicePayment = it
                    showInvoiceModal = true
                },
                onPayNow = {
                    selectedPaymentForCheckout = it
                    showCheckoutSheet = true
                },
                context = context,
                isEmbedded = true
            )
        }
    } else {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .background(Color(0xFFF8FAFC)),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                CustomerInvoicesContent(
                    payments = payments,
                    orders = orders,
                    totalSpent = totalSpent,
                    onSelectInvoice = {
                        selectedInvoicePayment = it
                        showInvoiceModal = true
                    },
                    onPayNow = {
                        selectedPaymentForCheckout = it
                        showCheckoutSheet = true
                    },
                    context = context
                )
            }
            item {
                Spacer(modifier = Modifier.height(80.dp))
            }
        }
    }

    // --- GST TAX INVOICE TEMPLATE MODAL DIALOG ---
    if (showInvoiceModal && selectedInvoicePayment != null) {
        val inv = selectedInvoicePayment!!
        val userName = (sessionManager.getUserName() ?: "").ifEmpty { inv.customerName.ifEmpty { "Client" } }
        val userEmail = (sessionManager.getUserEmail() ?: "").ifEmpty { inv.email }
        val userPhone = sessionManager.getPhone().ifEmpty { inv.phone }
        val compName = (sessionManager.getCompanyName() ?: "").ifEmpty { userName }

        val subtotal = inv.amount / 1.18
        val gstTax = inv.amount - subtotal
        val cgst = gstTax / 2.0
        val sgst = gstTax / 2.0

        val invoiceDateStr = if (inv.createdAt.length >= 10) inv.createdAt.substring(0, 10) else "2026-09-19"
        val invoiceNoStr = "INV-${inv.id.takeLast(6).uppercase()}"

        GSTSalesInvoiceTemplateModal(
            invoiceNumber = invoiceNoStr,
            invoiceDate = invoiceDateStr,
            dueDate = null,
            clientName = compName,
            clientAddress = "Telangana, India",
            clientGstin = "36AABCS9912D1Z4",
            clientEmail = userEmail,
            clientPhone = userPhone,
            items = listOf(
                GSTInvoiceItemData(
                    description = inv.serviceName.ifEmpty { "Professional Advisory & Business Services" },
                    hsn = "998311",
                    qty = 1,
                    rate = subtotal,
                    taxRate = 18.0,
                    amount = inv.amount
                )
            ),
            subtotal = subtotal,
            cgst = cgst,
            sgst = sgst,
            igst = 0.0,
            totalAmount = inv.amount,
            status = if (inv.status == "Paid" || inv.status == "Completed") "PAID" else inv.status,
            pdfUrl = inv.invoiceUrl,
            onDismiss = { showInvoiceModal = false }
        )
    }

    // --- PAYMENT SETTLEMENT CHECKOUT SHEET ---
    if (showCheckoutSheet && selectedPaymentForCheckout != null) {
        val p = selectedPaymentForCheckout!!
        CustomPaymentBottomSheet(
            key = "rzp_live_51P...",
            orderId = p.paymentId,
            amount = (p.amount * 100).toLong(),
            currency = p.currency.ifEmpty { "INR" },
            serviceName = p.serviceName,
            packageName = p.packageName.ifEmpty { "Standard Package" },
            customerName = (sessionManager.getUserName() ?: "").ifEmpty { "Customer" },
            customerEmail = (sessionManager.getUserEmail() ?: "").ifEmpty { "customer@vrhere.in" },
            customerPhone = "918008530606",
            onSuccess = { paymentId, orderId, signature ->
                showCheckoutSheet = false
                Toast.makeText(context, "Invoice payment successful!", Toast.LENGTH_LONG).show()
                viewModel.refreshAllData(silent = true)
            },
            onFailure = { err ->
                Toast.makeText(context, "Payment failed: $err", Toast.LENGTH_LONG).show()
            },
            onClose = { showCheckoutSheet = false }
        )
    }
}

@Composable
private fun CustomerInvoicesContent(
    payments: List<PaymentResponse>,
    orders: List<OrderResponse>,
    totalSpent: Double,
    onSelectInvoice: (PaymentResponse) -> Unit,
    onPayNow: (PaymentResponse) -> Unit,
    context: Context,
    isEmbedded: Boolean = false
) {
    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        if (!isEmbedded) {
            // --- 1. HERO HEADER & GST BADGE (Standalone view only) ---
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Billing & Invoices", fontSize = 22.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                    Text("View & download service estimates, proforma & GST tax invoices.", fontSize = 12.sp, color = Color(0xFF64748B))
                }
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = Color(0xFFECFDF5),
                    border = BorderStroke(1.dp, Color(0xFFA7F3D0))
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    ) {
                        Icon(Icons.Default.Verified, contentDescription = null, tint = Color(0xFF047857), modifier = Modifier.size(12.dp))
                        Text("GST COMPLIANT", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF047857))
                    }
                }
            }
        }

        // Financial Summary Dark Card
        Card(
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color.Transparent),
            modifier = Modifier.fillMaxWidth()
        ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            brush = Brush.linearGradient(
                                listOf(Color(0xFF0F172A), Color(0xFF1E293B))
                            ),
                            shape = RoundedCornerShape(24.dp)
                        )
                        .padding(20.dp)
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text("TOTAL VERIFIED INVESTMENT", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8), letterSpacing = 0.5.sp)
                                Text("₹${String.format("%,.0f", totalSpent)}", fontSize = 28.sp, fontWeight = FontWeight.Black, color = Color.White)
                            }
                            Surface(
                                shape = CircleShape,
                                color = Color.White.copy(alpha = 0.1f)
                            ) {
                                Icon(Icons.Default.AccountBalanceWallet, contentDescription = null, tint = Color(0xFF34D399), modifier = Modifier.padding(10.dp).size(22.dp))
                            }
                        }

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Surface(
                                shape = RoundedCornerShape(12.dp),
                                color = Color.White.copy(alpha = 0.05f),
                                border = BorderStroke(1.dp, Color.White.copy(alpha = 0.1f)),
                                modifier = Modifier.weight(1f)
                            ) {
                                Column(modifier = Modifier.padding(10.dp)) {
                                    Text("TRANSACTIONS", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                                    Text("${payments.size}", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color.White)
                                }
                            }

                            Surface(
                                shape = RoundedCornerShape(12.dp),
                                color = Color.White.copy(alpha = 0.05f),
                                border = BorderStroke(1.dp, Color.White.copy(alpha = 0.1f)),
                                modifier = Modifier.weight(1f)
                            ) {
                                Column(modifier = Modifier.padding(10.dp)) {
                                    Text("ACTIVE ORDERS", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                                    Text("${orders.size}", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color.White)
                                }
                            }
                        }
                    }
                }
            }

        // --- 2. INVOICE LIST SECTION ---
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("Invoices & Payment Records", fontSize = 15.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
            Text("${payments.size} Total", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF64748B))
        }

        if (payments.isEmpty()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(
                    modifier = Modifier
                        .padding(32.dp)
                        .fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(Icons.Default.ReceiptLong, contentDescription = null, tint = Color.LightGray, modifier = Modifier.size(44.dp))
                    Text("No billing history yet", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF64748B))
                    Text("Your tax invoices will appear here once orders are initiated.", fontSize = 11.sp, color = Color(0xFF94A3B8), textAlign = TextAlign.Center)
                }
            }
        } else {
            payments.forEach { payment ->
                val isPaid = payment.status == "Completed" || payment.status == "Paid"
                val isCancelled = payment.status == "Cancelled"

                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onSelectInvoice(payment) },
                    shape = RoundedCornerShape(18.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                    elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                ) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Surface(
                                    shape = RoundedCornerShape(6.dp),
                                    color = Color(0xFFEEF2FF)
                                ) {
                                    Text("TAX INVOICE", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF4338CA), modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                                }
                                Text("#${payment.id.takeLast(8).uppercase()}", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF64748B))
                            }

                            Surface(
                                shape = RoundedCornerShape(6.dp),
                                color = if (isPaid) Color(0xFFD1FAE5) else if (isCancelled) Color(0xFFFEF2F2) else Color(0xFFFEF3C7)
                            ) {
                                Text(
                                    text = payment.status.uppercase(),
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Black,
                                    color = if (isPaid) Color(0xFF047857) else if (isCancelled) Color(0xFFBE123C) else Color(0xFFB45309),
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 3.dp)
                                )
                            }
                        }

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = payment.serviceName.ifEmpty { "Business Compliance Service" },
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF0F172A)
                                )
                                Text(
                                    text = "Date: ${if (payment.createdAt.length >= 10) payment.createdAt.substring(0, 10) else "Recent"} • ${payment.method}",
                                    fontSize = 11.sp,
                                    color = Color(0xFF64748B)
                                )
                            }

                            Text("₹${payment.amount.toInt()}", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                        }

                        HorizontalDivider(color = Color(0xFFF1F5F9))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            // View GST Invoice Template Dialog Button
                            Button(
                                onClick = { onSelectInvoice(payment) },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF0F172A)),
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.weight(1f),
                                contentPadding = PaddingValues(vertical = 6.dp)
                            ) {
                                Icon(Icons.Default.Receipt, contentDescription = null, modifier = Modifier.size(14.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("GST Tax Invoice", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                            }

                            // Download / View direct PDF link if available
                            if (!payment.invoiceUrl.isNullOrEmpty()) {
                                OutlinedButton(
                                    onClick = { openDocumentUrl(context, payment.invoiceUrl) },
                                    shape = RoundedCornerShape(10.dp),
                                    modifier = Modifier.weight(1f),
                                    contentPadding = PaddingValues(vertical = 6.dp)
                                ) {
                                    Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(14.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("Download PDF", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                }
                            }

                            // Pay Now if pending
                            if (!isPaid && !isCancelled) {
                                Button(
                                    onClick = { onPayNow(payment) },
                                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                                    shape = RoundedCornerShape(10.dp),
                                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp)
                                ) {
                                    Text("Pay Now", fontSize = 10.sp, fontWeight = FontWeight.Black)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
