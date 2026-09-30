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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
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
    val isSales = transaction.transactionType.equals("Sales", ignoreCase = true)
    val isPurchase = transaction.transactionType.equals("Purchase", ignoreCase = true)
    val isIncome = transaction.transactionType.equals("Income", ignoreCase = true)
    val isExpense = transaction.transactionType.equals("Expense", ignoreCase = true)
    val isVoucher = isIncome || isExpense

    val copyType = transaction.copyType.ifBlank { "Original for Recipient" }
    val docNumber = transaction.docNumber.ifBlank {
        when {
            isIncome -> "RV-0001"
            isExpense -> "PV-0001"
            isPurchase -> "PUR-0001"
            else -> "INV-0001"
        }
    }
    val docDate = transaction.docDate.take(10).ifBlank { "30/09/2026" }
    val dueDate = transaction.dueDate?.take(10)?.ifBlank { null } ?: docDate
    val paymentMode = transaction.paymentMode.ifBlank { "Bank Transfer" }
    val placeOfSupply = transaction.placeOfSupply.ifBlank { companyDetails?.state ?: "37-Andhra Pradesh" }

    val docTitle = when {
        isIncome -> "RECEIPT VOUCHER"
        isExpense -> "PAYMENT VOUCHER"
        isPurchase -> "PURCHASE INVOICE"
        else -> "TAX INVOICE"
    }

    val supplierName = if (isSales || isVoucher) {
        companyDetails?.companyName?.ifBlank { null } ?: "Rajugari Ventures"
    } else {
        transaction.partyName.ifBlank { "Vendor Name" }
    }
    val supplierAddress = if (isSales || isVoucher) {
        companyDetails?.address?.ifBlank { null } ?: "#38, 1st Floor, TUDA Complex, Bairagipatteda, Tirupati"
    } else {
        transaction.partyAddress
    }
    val supplierGstin = if (isSales || isVoucher) companyDetails?.gstin ?: "" else transaction.partyGstin
    val supplierState = if (isSales || isVoucher) companyDetails?.state ?: "Andhra Pradesh" else placeOfSupply
    val supplierPhone = if (isSales || isVoucher) companyDetails?.phone ?: "" else transaction.partyPhone
    val supplierEmail = if (isSales || isVoucher) companyDetails?.email ?: "" else transaction.partyEmail

    // Bill To
    val billToName = if (isSales) {
        transaction.partyName.ifBlank { "Rajugari Ventures" }
    } else if (isVoucher) {
        transaction.partyName.ifBlank { "General" }
    } else {
        companyDetails?.companyName ?: "Rajugari Ventures"
    }
    val billToAddress = if (isSales) {
        transaction.partyAddress.ifBlank { "#38, 1st Floor, TUDA Complex, Bairagipatteda" }
    } else {
        companyDetails?.address ?: "#38, 1st Floor, TUDA Complex"
    }
    val billToGstin = if (isSales) transaction.partyGstin.ifBlank { "URP / N/A" } else companyDetails?.gstin ?: "N/A"
    val billToPan = if (isSales) transaction.partyPan.ifBlank { "N/A" } else "N/A"
    val billToState = if (isSales) transaction.partyState.ifBlank { placeOfSupply } else companyDetails?.state ?: "Andhra Pradesh"
    val billToPhone = if (isSales) transaction.partyPhone.ifBlank { "N/A" } else companyDetails?.phone ?: "N/A"
    val billToEmail = if (isSales) transaction.partyEmail.ifBlank { "N/A" } else companyDetails?.email ?: "N/A"

    // Ship To
    val shipToSame = transaction.shipToSameAsBilling
    val shipToName = if (shipToSame) billToName else transaction.shipToName.ifBlank { billToName }
    val shipToAddress = if (shipToSame) billToAddress else transaction.shipToAddress.ifBlank { billToAddress }
    val shipToGstin = if (shipToSame) billToGstin else transaction.shipToGstin.ifBlank { billToGstin }
    val shipToPan = if (shipToSame) billToPan else transaction.shipToPan.ifBlank { billToPan }
    val shipToState = if (shipToSame) billToState else transaction.shipToState.ifBlank { billToState }
    val shipToPhone = if (shipToSame) billToPhone else transaction.shipToMobile.ifBlank { billToPhone }
    val shipToEmail = if (shipToSame) billToEmail else transaction.shipToEmail.ifBlank { billToEmail }

    // Bank Details
    val bankInfo = companyDetails?.bankDetails
    val bankName = bankInfo?.bankName?.ifBlank { null } ?: "HDFC Bank"
    val bankAccount = bankInfo?.accountNumber?.ifBlank { null } ?: "50200012345678"
    val bankIfsc = bankInfo?.ifscCode?.ifBlank { null } ?: "HDFC0001234"
    val bankBranch = bankInfo?.accountName?.ifBlank { null } ?: "Main Branch"
    val upiId = companyDetails?.upiId ?: ""

    val defaultTerms = listOf(
        "1. Payment: Payment must be made as per the terms and due date mentioned in the invoice.",
        "2. Taxes: GST and other applicable taxes will be charged as per prevailing laws.",
        "3. Disputes: Any discrepancy in the invoice must be reported within 7 days of receipt.",
        "4. Jurisdiction: Any disputes shall be subject to the jurisdiction of the seller's place of business."
    )

    val itemsList = if (transaction.items.isNotEmpty()) transaction.items else listOf(
        com.sbr.vrherebms.data.model.TransactionItemDto(
            description = "Professional Business Services",
            hsnSac = "998311",
            qty = 1.0,
            unit = "PCS",
            rate = 10000.0,
            taxableValue = 10000.0,
            gstRate = 18.0,
            total = 11800.0
        )
    )

    val summary = transaction.summary
    val totalAmount = if (summary.totalAmount > 0) summary.totalAmount else itemsList.sumOf { it.total }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 6.dp, vertical = 12.dp),
            shape = RoundedCornerShape(16.dp),
            color = Color(0xFFF1F5F9),
            shadowElevation = 10.dp
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(10.dp)
            ) {
                // Top Web-Style Actions Bar
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = Color.White,
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                    modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        TextButton(
                            onClick = onDismiss,
                            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                        ) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = Color(0xFF334155), modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Back", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF334155))
                        }

                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            Button(
                                onClick = {
                                    InvoicePdfGenerator.sharePdf(context, transaction, companyDetails, targetWhatsApp = true)
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF059669)),
                                shape = RoundedCornerShape(10.dp),
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp),
                                modifier = Modifier.height(34.dp)
                            ) {
                                Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(13.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("WhatsApp", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            }

                            Button(
                                onClick = {
                                    InvoicePdfGenerator.sharePdf(context, transaction, companyDetails, targetWhatsApp = false)
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF1F5F9)),
                                shape = RoundedCornerShape(10.dp),
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp),
                                modifier = Modifier.height(34.dp)
                            ) {
                                Text("Share PDF", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF334155))
                            }

                            Button(
                                onClick = {
                                    InvoicePdfGenerator.downloadAndOpenPdf(context, transaction, companyDetails)
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                                shape = RoundedCornerShape(10.dp),
                                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                                modifier = Modifier.height(34.dp)
                            ) {
                                Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(13.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Print / Save PDF", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }

                // Scrollable Document Sheet (Supporting horizontal + vertical scroll for 100% desktop fidelity)
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState())
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState())
                    ) {
                        // Desktop A4 Sized Sheet (720dp fixed width representation)
                        Column(
                            modifier = Modifier
                                .width(720.dp)
                                .background(Color.White, RoundedCornerShape(12.dp))
                                .padding(16.dp)
                        ) {
                            // Top Copy Type Indicator
                            Row(modifier = Modifier.fillMaxWidth().padding(bottom = 4.dp), horizontalArrangement = Arrangement.End) {
                                Surface(
                                    shape = RoundedCornerShape(4.dp),
                                    color = Color(0xFFF1F5F9),
                                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                                ) {
                                    Text(
                                        text = "copy : ${copyType.lowercase()}",
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color(0xFF64748B),
                                        letterSpacing = 0.8.sp,
                                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                                    )
                                }
                            }

                            // 1. Header Box
                            Surface(
                                shape = RoundedCornerShape(topStart = 10.dp, topEnd = 10.dp),
                                color = Color(0xFFF8FAFC),
                                border = BorderStroke(2.dp, Color(0xFF0F172A)),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Row(
                                    modifier = Modifier.padding(14.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    // Supplier Left
                                    Column(modifier = Modifier.weight(1.3f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                        Text(supplierName, fontSize = 18.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                        Text(supplierAddress, fontSize = 10.5.sp, color = Color(0xFF475569))
                                        Row {
                                            Text("GSTIN: ", fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                            Text(supplierGstin.ifBlank { "37ABCDE1234F1Z5" }, fontSize = 10.5.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                            Text("  |  State: $supplierState", fontSize = 10.5.sp, color = Color(0xFF0F172A))
                                        }
                                        if (supplierPhone.isNotBlank() || supplierEmail.isNotBlank()) {
                                            Text("Phone: ${supplierPhone.ifBlank { "07997991101" }}  |  Email: ${supplierEmail.ifBlank { "N/A" }}", fontSize = 10.sp, color = Color(0xFF64748B))
                                        }
                                    }

                                    // Invoice Meta Right
                                    Column(
                                        modifier = Modifier.weight(0.9f).padding(start = 14.dp),
                                        horizontalAlignment = Alignment.End,
                                        verticalArrangement = Arrangement.spacedBy(3.dp)
                                    ) {
                                        Surface(
                                            shape = RoundedCornerShape(4.dp),
                                            color = Color(0xFF0F172A),
                                            modifier = Modifier.fillMaxWidth()
                                        ) {
                                            Text(
                                                text = docTitle,
                                                fontSize = 11.sp,
                                                fontWeight = FontWeight.Black,
                                                color = Color.White,
                                                textAlign = TextAlign.Center,
                                                letterSpacing = 1.sp,
                                                modifier = Modifier.padding(vertical = 4.dp)
                                            )
                                        }

                                        Row(modifier = Modifier.fillMaxWidth().padding(top = 2.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                                            Text("Invoice No.:", fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = Color(0xFF475569))
                                            Text(docNumber, fontSize = 10.5.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace, color = Color(0xFF0F172A))
                                        }
                                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                            Text("Invoice Date:", fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = Color(0xFF475569))
                                            Text(docDate, fontSize = 10.5.sp, color = Color(0xFF0F172A))
                                        }
                                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                            Text("Due Date:", fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = Color(0xFF475569))
                                            Text(dueDate, fontSize = 10.5.sp, color = Color(0xFF0F172A))
                                        }
                                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                            Text("Place of Supply:", fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = Color(0xFF475569))
                                            Text(placeOfSupply, fontSize = 10.5.sp, color = Color(0xFF0F172A))
                                        }
                                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                            Text("Payment Mode:", fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = Color(0xFF475569))
                                            Text(paymentMode, fontSize = 10.5.sp, color = Color(0xFF0F172A))
                                        }
                                    }
                                }
                            }

                            // 2. Parties Block: BILL TO and SHIP TO
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .border(
                                        BorderStroke(2.dp, Color(0xFF0F172A))
                                    )
                            ) {
                                // BILL TO
                                Column(
                                    modifier = Modifier.weight(1f).padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(3.dp)
                                ) {
                                    Text(
                                        text = "BILL TO",
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Black,
                                        color = Color(0xFF312E81),
                                        modifier = Modifier.padding(bottom = 2.dp)
                                    )
                                    Text(billToName, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                    Text(billToAddress, fontSize = 10.sp, color = Color(0xFF475569))
                                    Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                                        Text("GSTIN: $billToGstin", fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = Color(0xFF0F172A))
                                        Text("PAN: $billToPan", fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = Color(0xFF0F172A))
                                    }
                                    Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                                        Text("State: $billToState", fontSize = 10.sp, color = Color(0xFF475569))
                                        Text("Mobile: $billToPhone", fontSize = 10.sp, color = Color(0xFF475569))
                                    }
                                    Text("Email: $billToEmail", fontSize = 10.sp, color = Color(0xFF475569))
                                }

                                Box(modifier = Modifier.width(1.dp).fillMaxHeight().background(Color(0xFFE2E8F0)))

                                // SHIP TO
                                Column(
                                    modifier = Modifier.weight(1f).padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(3.dp)
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        modifier = Modifier.fillMaxWidth().padding(bottom = 2.dp)
                                    ) {
                                        Text("SHIP TO (CONSIGNEE)", fontSize = 11.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                        if (shipToSame) {
                                            Text("(same as billing)", fontSize = 9.sp, color = Color(0xFF64748B))
                                        }
                                    }
                                    Text(shipToName, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                    Text(shipToAddress, fontSize = 10.sp, color = Color(0xFF475569))
                                    Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                                        Text("GSTIN: $shipToGstin", fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = Color(0xFF0F172A))
                                        Text("PAN: $shipToPan", fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = Color(0xFF0F172A))
                                    }
                                    Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                                        Text("State: $shipToState", fontSize = 10.sp, color = Color(0xFF475569))
                                        Text("Mobile: $shipToPhone", fontSize = 10.sp, color = Color(0xFF475569))
                                    }
                                    Text("Email: $shipToEmail", fontSize = 10.sp, color = Color(0xFF475569))
                                }
                            }

                            // 3. Compact 10-Column Items Table
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .border(BorderStroke(2.dp, Color(0xFF0F172A)))
                            ) {
                                // Table Header
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .background(Color(0xFF0F172A))
                                        .padding(vertical = 8.dp, horizontal = 6.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text("#", fontSize = 9.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.width(32.dp), textAlign = TextAlign.Center)
                                    Text("Item / Service Description", fontSize = 9.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.weight(1f))
                                    Text("HSN/SAC", fontSize = 9.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.width(65.dp), textAlign = TextAlign.Center)
                                    Text("Qty", fontSize = 9.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.width(36.dp), textAlign = TextAlign.Center)
                                    Text("Unit", fontSize = 9.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.width(42.dp), textAlign = TextAlign.Center)
                                    Text("Rate (₹)", fontSize = 9.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.width(65.dp), textAlign = TextAlign.End)
                                    Text("Disc %", fontSize = 9.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.width(46.dp), textAlign = TextAlign.End)
                                    Text("GST %", fontSize = 9.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.width(46.dp), textAlign = TextAlign.End)
                                    Text("Taxable (₹)", fontSize = 9.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.width(75.dp), textAlign = TextAlign.End)
                                    Text("Total (₹)", fontSize = 9.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.width(85.dp), textAlign = TextAlign.End)
                                }

                                itemsList.forEachIndexed { idx, item ->
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .background(if (idx % 2 == 0) Color.White else Color(0xFFF8FAFC))
                                            .padding(vertical = 8.dp, horizontal = 6.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text("${idx + 1}", fontSize = 9.5.sp, color = Color(0xFF64748B), modifier = Modifier.width(32.dp), textAlign = TextAlign.Center)
                                        Text(item.description, fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A), modifier = Modifier.weight(1f))
                                        Text(item.hsnSac.ifBlank { "-" }, fontSize = 9.5.sp, fontFamily = FontFamily.Monospace, color = Color(0xFF475569), modifier = Modifier.width(65.dp), textAlign = TextAlign.Center)
                                        Text("${item.qty}", fontSize = 9.5.sp, color = Color(0xFF0F172A), modifier = Modifier.width(36.dp), textAlign = TextAlign.Center)
                                        Text(item.unit.ifBlank { "PCS" }, fontSize = 9.5.sp, color = Color(0xFF64748B), modifier = Modifier.width(42.dp), textAlign = TextAlign.Center)
                                        Text("%.2f".format(item.rate), fontSize = 9.5.sp, fontFamily = FontFamily.Monospace, color = Color(0xFF0F172A), modifier = Modifier.width(65.dp), textAlign = TextAlign.End)
                                        Text(if (item.discPercent > 0) "${item.discPercent}%" else "-", fontSize = 9.5.sp, color = Color(0xFF64748B), modifier = Modifier.width(46.dp), textAlign = TextAlign.End)
                                        Text("${item.gstRate.toInt()}%", fontSize = 9.5.sp, color = Color(0xFF64748B), modifier = Modifier.width(46.dp), textAlign = TextAlign.End)
                                        Text("%.2f".format(item.taxableValue), fontSize = 9.5.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A), modifier = Modifier.width(75.dp), textAlign = TextAlign.End)
                                        Text("%.2f".format(item.total), fontSize = 10.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Black, color = Color(0xFF0F172A), modifier = Modifier.width(85.dp), textAlign = TextAlign.End)
                                    }
                                    if (idx < itemsList.size - 1) {
                                        HorizontalDivider(color = Color(0xFFE2E8F0))
                                    }
                                }
                            }

                            // 4. Totals and Calculations Block
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .border(BorderStroke(2.dp, Color(0xFF0F172A)))
                            ) {
                                // Left: Amount in Words & Notes
                                Column(
                                    modifier = Modifier.weight(1.3f).background(Color(0xFFF8FAFC)).padding(12.dp),
                                    verticalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                        Text("AMOUNT IN WORDS:", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF475569), letterSpacing = 0.5.sp)
                                        val words = summary.amountInWords.ifBlank { IndianCurrencyFormatter.numberToWords(totalAmount) }
                                        Text(words, fontSize = 10.5.sp, fontStyle = FontStyle.Italic, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                    }

                                    if (transaction.notes.isNotBlank()) {
                                        Text("Special Notes: ${transaction.notes}", fontSize = 9.5.sp, color = Color(0xFF475569), modifier = Modifier.padding(top = 8.dp))
                                    }
                                }

                                Box(modifier = Modifier.width(1.dp).fillMaxHeight().background(Color(0xFFCBD5E1)))

                                // Right: Totals
                                Column(
                                    modifier = Modifier.weight(1f).background(Color(0xFFF8FAFC)).padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(5.dp)
                                ) {
                                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                        Text("Subtotal (Taxable Value):", fontSize = 10.5.sp, color = Color(0xFF475569))
                                        Text("₹%.2f".format(if (summary.totalTaxableValue > 0) summary.totalTaxableValue else itemsList.sumOf { it.taxableValue }), fontSize = 10.5.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                    }
                                    if (summary.totalCgst > 0) {
                                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                            Text("Total CGST:", fontSize = 10.5.sp, color = Color(0xFF475569))
                                            Text("₹%.2f".format(summary.totalCgst), fontSize = 10.5.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                        }
                                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                            Text("Total SGST:", fontSize = 10.5.sp, color = Color(0xFF475569))
                                            Text("₹%.2f".format(summary.totalSgst), fontSize = 10.5.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                        }
                                    } else if (summary.totalIgst > 0) {
                                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                            Text("Total IGST:", fontSize = 10.5.sp, color = Color(0xFF475569))
                                            Text("₹%.2f".format(summary.totalIgst), fontSize = 10.5.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                        }
                                    }

                                    HorizontalDivider(color = Color(0xFF0F172A), thickness = 2.dp, modifier = Modifier.padding(top = 4.dp))

                                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                                        Text("GRAND TOTAL:", fontSize = 12.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                        Text(IndianCurrencyFormatter.format(totalAmount), fontSize = 14.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Black, color = Color(0xFF312E81))
                                    }
                                }
                            }

                            // 5. Footer: Bank Details & Terms
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .border(BorderStroke(2.dp, Color(0xFF0F172A)))
                            ) {
                                // Bank Details
                                Column(
                                    modifier = Modifier.weight(1f).padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(3.dp)
                                ) {
                                    Text("BANK DETAILS", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A), letterSpacing = 0.5.sp)
                                    Text("Bank Name: $bankName", fontSize = 9.5.sp, color = Color(0xFF475569))
                                    Text("Account No.: $bankAccount", fontSize = 9.5.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                    Text("IFSC Code: $bankIfsc", fontSize = 9.5.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                    Text("Branch: $bankBranch", fontSize = 9.5.sp, color = Color(0xFF475569))
                                    if (upiId.isNotBlank()) {
                                        Text("UPI ID: $upiId", fontSize = 9.5.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, color = Color(0xFF4F46E5))
                                    }
                                }

                                Box(modifier = Modifier.width(1.dp).fillMaxHeight().background(Color(0xFFCBD5E1)))

                                // Terms & Conditions
                                Column(
                                    modifier = Modifier.weight(1.3f).padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(2.dp)
                                ) {
                                    Text("TERMS & CONDITIONS", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A), letterSpacing = 0.5.sp)
                                    defaultTerms.forEach { t ->
                                        Text(t, fontSize = 9.sp, color = Color(0xFF475569), lineHeight = 12.sp)
                                    }
                                }
                            }

                            // 6. Declaration & Signatory
                            Surface(
                                shape = RoundedCornerShape(bottomStart = 10.dp, bottomEnd = 10.dp),
                                color = Color(0xFFF8FAFC),
                                border = BorderStroke(2.dp, Color(0xFF0F172A)),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Row(
                                    modifier = Modifier.padding(12.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = "Declaration: We declare that this invoice shows the actual price of the goods/services described and that all particulars are true and correct.",
                                        fontSize = 9.5.sp,
                                        fontStyle = FontStyle.Italic,
                                        color = Color(0xFF64748B),
                                        modifier = Modifier.weight(1.3f)
                                    )

                                    Column(
                                        modifier = Modifier.weight(0.9f),
                                        horizontalAlignment = Alignment.CenterHorizontally,
                                        verticalArrangement = Arrangement.spacedBy(2.dp)
                                    ) {
                                        Spacer(modifier = Modifier.height(20.dp))
                                        HorizontalDivider(color = Color(0xFF94A3B8), thickness = 1.dp, modifier = Modifier.width(140.dp))
                                        Text("Authorized Signatory", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                        Text(supplierName.uppercase(), fontSize = 8.5.sp, fontWeight = FontWeight.Bold, color = Color(0xFF64748B))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
