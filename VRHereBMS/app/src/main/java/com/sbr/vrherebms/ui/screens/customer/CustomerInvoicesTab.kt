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
import com.sbr.vrherebms.data.model.BankAccountDetailsDto
import com.sbr.vrherebms.data.model.CompanyDetailsDto
import com.sbr.vrherebms.data.model.OrderResponse
import com.sbr.vrherebms.data.model.PaymentResponse
import com.sbr.vrherebms.data.model.TransactionDto
import com.sbr.vrherebms.data.model.TransactionItemDto
import com.sbr.vrherebms.data.model.TransactionSummaryDto
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.dialogs.GSTInvoicePreviewDialog
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel

data class UnifiedInvoiceItem(
    val id: String,
    val orderId: String,
    val invoiceNumber: String,
    val serviceName: String,
    val packageName: String = "Standard Package",
    val date: String,
    val dueDate: String? = null,
    val amount: Double,
    val status: String,
    val isPaid: Boolean,
    val canPayNow: Boolean,
    val directUrl: String = "",
    val paymentId: String = ""
)

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

    // Aggregate ALL Invoices across Orders, Milestones & Payments
    val unifiedInvoices = remember(payments, orders) {
        val list = mutableListOf<UnifiedInvoiceItem>()
        val processedNumbers = mutableSetOf<String>()

        // 1. Add all explicit milestone invoices from orders (e.g. INV-0310260001)
        orders.forEach { order ->
            order.invoices.forEach { inv ->
                val isPaid = inv.status.equals("Paid", ignoreCase = true) || inv.status.equals("Completed", ignoreCase = true)
                val canPay = !isPaid && !inv.status.equals("Cancelled", ignoreCase = true) && !inv.status.equals("Draft", ignoreCase = true)
                val invNum = if (inv.number.isNotBlank()) inv.number else "INV-${inv.id.takeLast(6).uppercase()}"
                if (processedNumbers.add(invNum.uppercase())) {
                    list.add(
                        UnifiedInvoiceItem(
                            id = inv.id.ifBlank { "inv_${order.id}_${inv.number}" },
                            orderId = order.id,
                            invoiceNumber = invNum,
                            serviceName = order.serviceName,
                            packageName = order.packageName,
                            date = if (inv.createdAt.length >= 10) inv.createdAt.substring(0, 10) else (if (order.createdAt.length >= 10) order.createdAt.substring(0, 10) else "Recent"),
                            dueDate = inv.dueDate,
                            amount = inv.amount,
                            status = inv.status,
                            isPaid = isPaid,
                            canPayNow = canPay,
                            directUrl = inv.url
                        )
                    )
                }
            }
        }

        // 2. Add orders that have an unpaid balance and NO separate milestone invoices
        orders.forEach { order ->
            val hasMilestoneInvoices = order.invoices.isNotEmpty()
            if (!hasMilestoneInvoices) {
                val orderPayments = payments.filter { p -> 
                    p.order?.id == order.id || (p.paymentId.isNotBlank() && p.paymentId == order.paymentId) 
                }
                val paidForOrder = orderPayments.filter { it.status.equals("Completed", ignoreCase = true) || it.status.equals("Paid", ignoreCase = true) }.sumOf { it.amount }
                val isOrderPaid = order.paymentStatus.equals("Paid", ignoreCase = true) || (order.paymentId.isNotBlank() && paidForOrder >= order.price)
                val balance = if (isOrderPaid) 0.0 else maxOf(0.0, order.price - paidForOrder)
                val invNum = "INV-${order.id.takeLast(8).uppercase()}"

                if (!isOrderPaid && balance > 0.0 && processedNumbers.add(invNum.uppercase())) {
                    list.add(
                        UnifiedInvoiceItem(
                            id = order.id,
                            orderId = order.id,
                            invoiceNumber = invNum,
                            serviceName = order.serviceName,
                            packageName = order.packageName,
                            date = if (order.createdAt.length >= 10) order.createdAt.substring(0, 10) else "Recent",
                            amount = balance,
                            status = if (paidForOrder > 0.0) "Partially Paid" else "Pending",
                            isPaid = false,
                            canPayNow = true,
                            directUrl = ""
                        )
                    )
                }
            }
        }

        // 3. Add all recorded payments
        payments.forEach { p ->
            val pInvNumber = "INV-${(p.paymentId.ifBlank { p.id }).takeLast(8).uppercase()}"
            val isPaid = p.status.equals("Completed", ignoreCase = true) || p.status.equals("Paid", ignoreCase = true)
            if (processedNumbers.add(pInvNumber.uppercase())) {
                list.add(
                    UnifiedInvoiceItem(
                        id = p.id,
                        orderId = p.order?.id ?: "",
                        invoiceNumber = pInvNumber,
                        serviceName = p.serviceName.ifBlank { p.order?.serviceName ?: "Professional Compliance & Legal Services" },
                        packageName = p.packageName.ifBlank { "Standard Package" },
                        date = if (p.createdAt.length >= 10) p.createdAt.substring(0, 10) else "Recent",
                        amount = p.amount,
                        status = if (isPaid) "Paid" else p.status,
                        isPaid = isPaid,
                        canPayNow = !isPaid && !p.status.equals("Cancelled", ignoreCase = true),
                        directUrl = p.invoiceUrl ?: "",
                        paymentId = p.paymentId
                    )
                )
            }
        }

        list
    }

    val totalSpent = remember(unifiedInvoices) {
        unifiedInvoices.filter { it.isPaid }.sumOf { it.amount }
    }

    // GST Invoice Modal View State
    var selectedInvoiceItem by remember { mutableStateOf<UnifiedInvoiceItem?>(null) }
    var showInvoiceModal by remember { mutableStateOf(false) }

    // Payment Settlement Sheet State
    var selectedInvoiceForCheckout by remember { mutableStateOf<UnifiedInvoiceItem?>(null) }
    var showCheckoutSheet by remember { mutableStateOf(false) }

    if (isEmbedded) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            CustomerInvoicesContent(
                invoices = unifiedInvoices,
                orders = orders,
                totalSpent = totalSpent,
                onSelectInvoice = {
                    selectedInvoiceItem = it
                    showInvoiceModal = true
                },
                onPayNow = {
                    selectedInvoiceForCheckout = it
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
                    invoices = unifiedInvoices,
                    orders = orders,
                    totalSpent = totalSpent,
                    onSelectInvoice = {
                        selectedInvoiceItem = it
                        showInvoiceModal = true
                    },
                    onPayNow = {
                        selectedInvoiceForCheckout = it
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

    // --- GST TAX INVOICE PREVIEW DIALOG (A4 Standard) ---
    if (showInvoiceModal && selectedInvoiceItem != null) {
        val inv = selectedInvoiceItem!!
        val userName = (sessionManager.getUserName() ?: "").ifEmpty { "Valued Customer" }
        val userEmail = (sessionManager.getUserEmail() ?: "").ifEmpty { "support@vrhere.in" }
        val userPhone = sessionManager.getPhone().ifEmpty { "+91 80085 30606" }
        val compName = (sessionManager.getCompanyName() ?: "").ifEmpty { userName }

        val subtotal = inv.amount / 1.18
        val gstTax = inv.amount - subtotal
        val cgst = gstTax / 2.0
        val sgst = gstTax / 2.0

        val vrHereSellerDetails = CompanyDetailsDto(
            companyName = "VR HERE BUSINESS MANAGEMENT SOLUTIONS PRIVATE LIMITED",
            tradeName = "VR HERE",
            gstin = "37AAHCR7654E1Z8",
            address = "#38, 1st Floor, TUDA Complex, Bairagipatteda, Tirupati, Andhra Pradesh - 517501",
            state = "Andhra Pradesh",
            phone = "+91 80085 30606",
            email = "support@vrhere.in",
            businessType = "Private Limited",
            bankDetails = BankAccountDetailsDto(
                accountName = "VR HERE BUSINESS MANAGEMENT SOLUTIONS PRIVATE LIMITED",
                accountNumber = "50200085306061",
                ifscCode = "HDFC0001234",
                bankName = "HDFC Bank, Tirupati"
            ),
            upiId = "vrhere@hdfcbank"
        )

        val invoiceTransaction = TransactionDto(
            id = inv.id,
            transactionType = "Sales",
            copyType = "Original for Recipient",
            docNumber = inv.invoiceNumber,
            docDate = inv.date,
            dueDate = inv.dueDate,
            paymentMode = "Razorpay / Online",
            partyName = compName,
            partyEmail = userEmail,
            partyPhone = userPhone,
            partyAddress = "Registered Customer Jurisdiction",
            partyGstin = "URP / N/A",
            partyState = "Andhra Pradesh",
            placeOfSupply = "37-Andhra Pradesh",
            isInterstate = false,
            items = listOf(
                TransactionItemDto(
                    description = inv.serviceName.ifEmpty { "Professional Advisory & Statutory Compliance Services" },
                    hsnSac = "998311",
                    qty = 1.0,
                    unit = "NOS",
                    rate = subtotal,
                    taxableValue = subtotal,
                    gstRate = 18.0,
                    cgst = cgst,
                    sgst = sgst,
                    igst = 0.0,
                    total = inv.amount
                )
            ),
            summary = TransactionSummaryDto(
                totalTaxableValue = subtotal,
                totalCgst = cgst,
                totalSgst = sgst,
                totalIgst = 0.0,
                totalAmount = inv.amount
            ),
            paymentStatus = if (inv.isPaid) "Paid" else inv.status,
            paidAmount = if (inv.isPaid) inv.amount else 0.0,
            status = "Verified"
        )

        GSTInvoicePreviewDialog(
            transaction = invoiceTransaction,
            companyDetails = vrHereSellerDetails,
            onDismiss = { showInvoiceModal = false }
        )
    }

    // --- PAYMENT SETTLEMENT CHECKOUT SHEET ---
    if (showCheckoutSheet && selectedInvoiceForCheckout != null) {
        val inv = selectedInvoiceForCheckout!!
        CustomPaymentBottomSheet(
            key = "rzp_live_51P...",
            orderId = inv.orderId.ifEmpty { inv.id },
            amount = (inv.amount * 100).toLong(),
            currency = "INR",
            serviceName = inv.serviceName,
            packageName = inv.packageName,
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
    invoices: List<UnifiedInvoiceItem>,
    orders: List<OrderResponse>,
    totalSpent: Double,
    onSelectInvoice: (UnifiedInvoiceItem) -> Unit,
    onPayNow: (UnifiedInvoiceItem) -> Unit,
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
                                Text("INVOICES & RECEIPTS", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                                Text("${invoices.size}", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color.White)
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
            Text("${invoices.size} Total", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF64748B))
        }

        if (invoices.isEmpty()) {
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
            invoices.forEach { invoice ->
                val isPaid = invoice.isPaid
                val isCancelled = invoice.status.equals("Cancelled", ignoreCase = true)
                val isPendingOrSent = invoice.status.equals("Sent", ignoreCase = true) || invoice.status.equals("Pending", ignoreCase = true) || invoice.status.equals("Overdue", ignoreCase = true) || invoice.status.equals("Partially Paid", ignoreCase = true)

                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onSelectInvoice(invoice) },
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
                                Text("#${invoice.invoiceNumber}", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF64748B))
                            }

                            Surface(
                                shape = RoundedCornerShape(6.dp),
                                color = if (isPaid) Color(0xFFD1FAE5) else if (isCancelled) Color(0xFFFEF2F2) else Color(0xFFFEF3C7)
                            ) {
                                Text(
                                    text = invoice.status.uppercase(),
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
                                    text = invoice.serviceName.ifEmpty { "Business Compliance Service" },
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF0F172A)
                                )
                                Text(
                                    text = "Date: ${invoice.date}${if (!invoice.dueDate.isNullOrBlank()) " • Due: ${invoice.dueDate}" else ""}",
                                    fontSize = 11.sp,
                                    color = Color(0xFF64748B)
                                )
                            }

                            Text("₹${invoice.amount.toInt()}", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                        }

                        HorizontalDivider(color = Color(0xFFF1F5F9))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            // View GST Invoice Template Dialog Button
                            Button(
                                onClick = { onSelectInvoice(invoice) },
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
                            if (invoice.directUrl.isNotBlank()) {
                                OutlinedButton(
                                    onClick = { openDocumentUrl(context, invoice.directUrl) },
                                    shape = RoundedCornerShape(10.dp),
                                    modifier = Modifier.weight(1f),
                                    contentPadding = PaddingValues(vertical = 6.dp)
                                ) {
                                    Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(14.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("Download PDF", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                }
                            }

                            // Pay Now if pending / sent / overdue
                            if (invoice.canPayNow) {
                                Button(
                                    onClick = { onPayNow(invoice) },
                                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                                    shape = RoundedCornerShape(10.dp),
                                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
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
