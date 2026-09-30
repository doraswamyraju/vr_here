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
    val primaryIndigo = Color(0xFF4F46E5)
    val textDark = Color(0xFF0F172A)
    val textMuted = Color(0xFF64748B)

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
    val dueDate = transaction.dueDate.take(10).ifBlank { docDate }
    val paymentMode = transaction.paymentMode.ifBlank { transaction.paymentType.ifBlank { "Bank Transfer" } }
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

    val totalAmount = if (transaction.summary.totalAmount > 0) transaction.summary.totalAmount else transaction.items.sumOf { it.total }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 8.dp, vertical = 16.dp),
            shape = RoundedCornerShape(16.dp),
            color = Color.White,
            shadowElevation = 8.dp
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(12.dp)
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
                            Text(docTitle, fontSize = 14.sp, fontWeight = FontWeight.Black, color = textDark)
                            Text(docNumber, fontSize = 11.sp, color = primaryIndigo, fontWeight = FontWeight.Bold)
                        }
                    }

                    // Share WhatsApp PDF & Download PDF Buttons
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Button(
                            onClick = {
                                InvoicePdfGenerator.sharePdf(context, transaction, companyDetails, targetWhatsApp = true)
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF16A34A)),
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
                            Text("Download", fontSize = 10.5.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }

                HorizontalDivider(color = Color(0xFFF1F5F9), modifier = Modifier.padding(vertical = 8.dp))

                // Scrollable Document Preview Container matching Web version 100%
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    // Copy Indicator
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                        Surface(
                            shape = RoundedCornerShape(4.dp),
                            color = Color(0xFFF1F5F9),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                        ) {
                            Text(
                                text = "COPY : ${copyType.uppercase()}",
                                fontSize = 8.5.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFF64748B),
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                            )
                        }
                    }

                    // Main Invoice Document Sheet
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(BorderStroke(1.5.dp, Color(0xFF0F172A)), RoundedCornerShape(8.dp))
                    ) {
                        // 1. Header Box
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(Color(0xFFF8FAFC), RoundedCornerShape(topStart = 8.dp, topEnd = 8.dp))
                                .padding(10.dp)
                        ) {
                            // Supplier Left
                            Column(modifier = Modifier.weight(1.3f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text(supplierName, fontSize = 13.5.sp, fontWeight = FontWeight.Black, color = textDark)
                                Text(supplierAddress, fontSize = 9.5.sp, color = Color(0xFF475569))
                                Text(
                                    "GSTIN: ${supplierGstin.ifBlank { "37ABCDE1234F1Z5" }} | State: $supplierState",
                                    fontSize = 9.5.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = textDark
                                )
                                Text("Phone: ${supplierPhone.ifBlank { "07997991101" }} | Email: ${supplierEmail.ifBlank { "N/A" }}", fontSize = 9.sp, color = textMuted)
                            }

                            // Meta Right
                            Column(
                                modifier = Modifier
                                    .weight(0.9f)
                                    .padding(start = 8.dp),
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
                                        fontSize = 9.5.sp,
                                        fontWeight = FontWeight.Black,
                                        color = Color.White,
                                        textAlign = TextAlign.Center,
                                        modifier = Modifier.padding(vertical = 3.dp)
                                    )
                                }

                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("Invoice No.:", fontSize = 9.sp, color = textMuted)
                                    Text(docNumber, fontSize = 9.sp, fontWeight = FontWeight.Bold, color = textDark)
                                }
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("Invoice Date:", fontSize = 9.sp, color = textMuted)
                                    Text(docDate, fontSize = 9.sp, color = textDark)
                                }
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("Due Date:", fontSize = 9.sp, color = textMuted)
                                    Text(dueDate, fontSize = 9.sp, color = textDark)
                                }
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("Place of Supply:", fontSize = 9.sp, color = textMuted)
                                    Text(placeOfSupply, fontSize = 9.sp, color = textDark)
                                }
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("Payment Mode:", fontSize = 9.sp, color = textMuted)
                                    Text(paymentMode, fontSize = 9.sp, color = textDark)
                                }
                            }
                        }

                        HorizontalDivider(color = Color(0xFF0F172A), thickness = 1.5.dp)

                        // 2. BILL TO & SHIP TO Boxes
                        Row(modifier = Modifier.fillMaxWidth()) {
                            // BILL TO
                            Column(
                                modifier = Modifier
                                    .weight(1f)
                                    .padding(8.dp),
                                verticalArrangement = Arrangement.spacedBy(2.dp)
                            ) {
                                Text("BILL TO", fontSize = 9.sp, fontWeight = FontWeight.Black, color = primaryIndigo)
                                Text(billToName, fontSize = 11.sp, fontWeight = FontWeight.Bold, color = textDark)
                                Text(billToAddress, fontSize = 9.sp, color = Color(0xFF475569))
                                Text("GSTIN: $billToGstin  PAN: $billToPan", fontSize = 8.5.sp, color = textDark)
                                Text("State: $billToState  Mobile: $billToPhone", fontSize = 8.5.sp, color = Color(0xFF475569))
                                Text("Email: $billToEmail", fontSize = 8.5.sp, color = Color(0xFF475569))
                            }

                            Box(modifier = Modifier.width(1.dp).fillMaxHeight().background(Color(0xFF0F172A)))

                            // SHIP TO
                            Column(
                                modifier = Modifier
                                    .weight(1f)
                                    .padding(8.dp),
                                verticalArrangement = Arrangement.spacedBy(2.dp)
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text("SHIP TO (Consignee)", fontSize = 9.sp, fontWeight = FontWeight.Black, color = textDark)
                                    if (shipToSame) {
                                        Text(" (same as billing)", fontSize = 7.5.sp, color = textMuted)
                                    }
                                }
                                Text(shipToName, fontSize = 11.sp, fontWeight = FontWeight.Bold, color = textDark)
                                Text(shipToAddress, fontSize = 9.sp, color = Color(0xFF475569))
                                Text("GSTIN: $shipToGstin  PAN: $shipToPan", fontSize = 8.5.sp, color = textDark)
                                Text("State: $shipToState  Mobile: $shipToPhone", fontSize = 8.5.sp, color = Color(0xFF475569))
                                Text("Email: $shipToEmail", fontSize = 8.5.sp, color = Color(0xFF475569))
                            }
                        }

                        HorizontalDivider(color = Color(0xFF0F172A), thickness = 1.5.dp)

                        // 3. Compact 10-Column Items Table (Horizontally scrollable for full desktop fidelity)
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .horizontalScroll(rememberScrollState())
                        ) {
                            // Table Header
                            Row(
                                modifier = Modifier
                                    .width(620.dp)
                                    .background(Color(0xFF0F172A))
                                    .padding(vertical = 6.dp, horizontal = 4.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("#", fontSize = 8.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.width(24.dp), textAlign = TextAlign.Center)
                                Text("Item / Service Description", fontSize = 8.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.width(170.dp))
                                Text("HSN/SAC", fontSize = 8.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.width(60.dp), textAlign = TextAlign.Center)
                                Text("Qty", fontSize = 8.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.width(36.dp), textAlign = TextAlign.Center)
                                Text("Unit", fontSize = 8.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.width(36.dp), textAlign = TextAlign.Center)
                                Text("Rate (₹)", fontSize = 8.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.width(55.dp), textAlign = TextAlign.End)
                                Text("Disc %", fontSize = 8.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.width(42.dp), textAlign = TextAlign.End)
                                Text("GST %", fontSize = 8.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.width(42.dp), textAlign = TextAlign.End)
                                Text("Taxable (₹)", fontSize = 8.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.width(70.dp), textAlign = TextAlign.End)
                                Text("Total (₹)", fontSize = 8.5.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.width(85.dp), textAlign = TextAlign.End)
                            }

                            // Items
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

                            itemsList.forEachIndexed { idx, item ->
                                Row(
                                    modifier = Modifier
                                        .width(620.dp)
                                        .background(if (idx % 2 == 0) Color.White else Color(0xFFF8FAFC))
                                        .padding(vertical = 6.dp, horizontal = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text("${idx + 1}", fontSize = 8.5.sp, color = textMuted, modifier = Modifier.width(24.dp), textAlign = TextAlign.Center)
                                    Text(item.description, fontSize = 8.5.sp, fontWeight = FontWeight.Bold, color = textDark, modifier = Modifier.width(170.dp))
                                    Text(item.hsnSac.ifBlank { "-" }, fontSize = 8.5.sp, color = Color(0xFF475569), modifier = Modifier.width(60.dp), textAlign = TextAlign.Center)
                                    Text("${item.qty}", fontSize = 8.5.sp, color = textDark, modifier = Modifier.width(36.dp), textAlign = TextAlign.Center)
                                    Text(item.unit.ifBlank { "PCS" }, fontSize = 8.5.sp, color = textMuted, modifier = Modifier.width(36.dp), textAlign = TextAlign.Center)
                                    Text("₹%.2f".format(item.rate), fontSize = 8.5.sp, color = textDark, modifier = Modifier.width(55.dp), textAlign = TextAlign.End)
                                    Text(if (item.discPercent > 0) "${item.discPercent}%" else "-", fontSize = 8.5.sp, color = textMuted, modifier = Modifier.width(42.dp), textAlign = TextAlign.End)
                                    Text("${item.gstRate.toInt()}%", fontSize = 8.5.sp, color = textMuted, modifier = Modifier.width(42.dp), textAlign = TextAlign.End)
                                    Text("₹%.2f".format(item.taxableValue), fontSize = 8.5.sp, fontWeight = FontWeight.Bold, color = textDark, modifier = Modifier.width(70.dp), textAlign = TextAlign.End)
                                    Text("₹%.2f".format(item.total), fontSize = 8.5.sp, fontWeight = FontWeight.Black, color = textDark, modifier = Modifier.width(85.dp), textAlign = TextAlign.End)
                                }
                                HorizontalDivider(color = Color(0xFFE2E8F0))
                            }
                        }

                        HorizontalDivider(color = Color(0xFF0F172A), thickness = 1.5.dp)

                        // 4. Totals and Calculations Block
                        Row(modifier = Modifier.fillMaxWidth()) {
                            // Left: Amount in Words & Notes
                            Column(
                                modifier = Modifier
                                    .weight(1.3f)
                                    .background(Color(0xFFF8FAFC))
                                    .padding(8.dp),
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Text("AMOUNT IN WORDS:", fontSize = 8.sp, fontWeight = FontWeight.Black, color = textMuted)
                                val words = transaction.summary.amountInWords.ifBlank { IndianCurrencyFormatter.numberToWords(totalAmount) }
                                Text(words, fontSize = 9.sp, fontWeight = FontWeight.Bold, color = textDark)
                                if (transaction.notes.isNotBlank()) {
                                    Text("Special Notes: ${transaction.notes}", fontSize = 8.sp, color = textMuted)
                                }
                            }

                            Box(modifier = Modifier.width(1.dp).fillMaxHeight().background(Color(0xFF0F172A)))

                            // Right: Totals
                            Column(
                                modifier = Modifier
                                    .weight(1f)
                                    .background(Color(0xFFF8FAFC))
                                    .padding(8.dp),
                                verticalArrangement = Arrangement.spacedBy(3.dp)
                            ) {
                                val summary = transaction.summary
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("Subtotal (Taxable):", fontSize = 8.5.sp, color = textMuted)
                                    Text("₹%.2f".format(if (summary.totalTaxableValue > 0) summary.totalTaxableValue else transaction.items.sumOf { it.taxableValue }), fontSize = 8.5.sp, fontWeight = FontWeight.Bold, color = textDark)
                                }
                                if (summary.totalCgst > 0) {
                                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                        Text("Total CGST:", fontSize = 8.5.sp, color = textMuted)
                                        Text("₹%.2f".format(summary.totalCgst), fontSize = 8.5.sp, fontWeight = FontWeight.Bold, color = textDark)
                                    }
                                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                        Text("Total SGST:", fontSize = 8.5.sp, color = textMuted)
                                        Text("₹%.2f".format(summary.totalSgst), fontSize = 8.5.sp, fontWeight = FontWeight.Bold, color = textDark)
                                    }
                                } else if (summary.totalIgst > 0) {
                                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                        Text("Total IGST:", fontSize = 8.5.sp, color = textMuted)
                                        Text("₹%.2f".format(summary.totalIgst), fontSize = 8.5.sp, fontWeight = FontWeight.Bold, color = textDark)
                                    }
                                }
                                HorizontalDivider(color = Color(0xFF0F172A), thickness = 1.dp)
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("GRAND TOTAL:", fontSize = 9.5.sp, fontWeight = FontWeight.Black, color = textDark)
                                    Text(IndianCurrencyFormatter.format(totalAmount), fontSize = 11.sp, fontWeight = FontWeight.Black, color = primaryIndigo)
                                }
                            }
                        }

                        HorizontalDivider(color = Color(0xFF0F172A), thickness = 1.5.dp)

                        // 5. Footer: Bank Details & Terms & Conditions
                        Row(modifier = Modifier.fillMaxWidth()) {
                            // Bank Details
                            Column(
                                modifier = Modifier
                                    .weight(1f)
                                    .padding(8.dp),
                                verticalArrangement = Arrangement.spacedBy(2.dp)
                            ) {
                                Text("BANK DETAILS", fontSize = 8.5.sp, fontWeight = FontWeight.Black, color = textDark)
                                Text("Bank Name: $bankName", fontSize = 8.sp, color = Color(0xFF475569))
                                Text("Account No.: $bankAccount", fontSize = 8.sp, fontWeight = FontWeight.Bold, color = textDark)
                                Text("IFSC Code: $bankIfsc", fontSize = 8.sp, fontWeight = FontWeight.Bold, color = textDark)
                                Text("Branch: $bankBranch", fontSize = 8.sp, color = Color(0xFF475569))
                                if (upiId.isNotBlank()) {
                                    Text("UPI ID: $upiId", fontSize = 8.sp, fontWeight = FontWeight.Bold, color = primaryIndigo)
                                }
                            }

                            Box(modifier = Modifier.width(1.dp).fillMaxHeight().background(Color(0xFFCBD5E1)))

                            // Terms & Conditions
                            Column(
                                modifier = Modifier
                                    .weight(1.2f)
                                    .padding(8.dp),
                                verticalArrangement = Arrangement.spacedBy(2.dp)
                            ) {
                                Text("TERMS & CONDITIONS", fontSize = 8.5.sp, fontWeight = FontWeight.Black, color = textDark)
                                Text("1. Payment must be made as per agreed terms.", fontSize = 7.5.sp, color = textMuted)
                                Text("2. Taxes charged per prevailing GST regulations.", fontSize = 7.5.sp, color = textMuted)
                                Text("3. Disputes subject to seller's local jurisdiction.", fontSize = 7.5.sp, color = textMuted)
                            }
                        }

                        HorizontalDivider(color = Color(0xFFCBD5E1))

                        // 6. Declaration & Signatory
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(Color(0xFFF8FAFC), RoundedCornerShape(bottomStart = 8.dp, bottomEnd = 8.dp))
                                .padding(8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "Declaration: We declare that this invoice shows the actual price of the goods/services described and that all particulars are true and correct.",
                                fontSize = 7.5.sp,
                                color = textMuted,
                                modifier = Modifier.weight(1.3f)
                            )

                            Column(
                                modifier = Modifier.weight(0.9f),
                                horizontalAlignment = Alignment.CenterHorizontally,
                                verticalArrangement = Arrangement.spacedBy(2.dp)
                            ) {
                                Text("Authorized Signatory", fontSize = 8.5.sp, fontWeight = FontWeight.Black, color = textDark)
                                Text(supplierName.uppercase(), fontSize = 7.5.sp, fontWeight = FontWeight.Bold, color = textMuted)
                            }
                        }
                    }
                }
            }
        }
    }
}
