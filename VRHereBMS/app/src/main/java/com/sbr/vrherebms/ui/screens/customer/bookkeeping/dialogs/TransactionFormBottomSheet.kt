package com.sbr.vrherebms.ui.screens.customer.bookkeeping.dialogs

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.PartyDto
import com.sbr.vrherebms.data.model.TransactionDto
import com.sbr.vrherebms.data.model.TransactionItemDto
import com.sbr.vrherebms.data.model.TransactionSummaryDto
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.utils.IndianCurrencyFormatter
import java.text.SimpleDateFormat
import java.util.*
import kotlin.math.roundToInt

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TransactionFormBottomSheet(
    transactionType: String, // "Sales", "Purchase", "Expense", "Income"
    existingTransaction: TransactionDto? = null,
    parties: List<PartyDto> = emptyList(),
    onDismiss: () -> Unit,
    onSubmit: (TransactionDto) -> Unit
) {
    val context = LocalContext.current
    val primaryIndigo = Color(0xFF4F46E5)
    val textDark = Color(0xFF0F172A)
    val textMuted = Color(0xFF64748B)

    val todayDate = remember {
        SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(Date())
    }

    var docNumber by remember {
        mutableStateOf(
            existingTransaction?.docNumber ?: when (transactionType) {
                "Sales" -> "INV-${System.currentTimeMillis().toString().takeLast(6)}"
                "Purchase" -> "PUR-${System.currentTimeMillis().toString().takeLast(6)}"
                "Expense" -> "EXP-${System.currentTimeMillis().toString().takeLast(6)}"
                else -> "INC-${System.currentTimeMillis().toString().takeLast(6)}"
            }
        )
    }

    var docDate by remember { mutableStateOf(existingTransaction?.docDate?.take(10) ?: todayDate) }
    var dueDate by remember { mutableStateOf(existingTransaction?.dueDate?.take(10) ?: todayDate) }
    var paymentMode by remember { mutableStateOf(existingTransaction?.paymentMode ?: "Bank Transfer") }
    var paymentStatus by remember { mutableStateOf(existingTransaction?.paymentStatus ?: "Unpaid") }

    // Party Details
    var partyName by remember { mutableStateOf(existingTransaction?.partyName ?: "") }
    var partyGstin by remember { mutableStateOf(existingTransaction?.partyGstin ?: "") }
    var partyPan by remember { mutableStateOf(existingTransaction?.partyPan ?: "") }
    var partyAddress by remember { mutableStateOf(existingTransaction?.partyAddress ?: "") }
    var partyPhone by remember { mutableStateOf(existingTransaction?.partyPhone ?: "") }
    var placeOfSupply by remember { mutableStateOf(existingTransaction?.placeOfSupply ?: "37-Andhra Pradesh") }
    var isInterstate by remember { mutableStateOf(existingTransaction?.isInterstate ?: false) }
    var itcEligibility by remember { mutableStateOf(existingTransaction?.itcEligibility ?: if (transactionType == "Purchase") "Inputs" else "N/A") }

    // Line Items State
    var items by remember {
        mutableStateOf(
            existingTransaction?.items?.ifEmpty { null } ?: listOf(
                TransactionItemDto(
                    description = if (transactionType == "Expense") "Office Operational Expense" else "Professional Business Services",
                    hsnSac = "998311",
                    qty = 1.0,
                    unit = "PCS",
                    rate = 10000.0,
                    discPercent = 0.0,
                    taxableValue = 10000.0,
                    gstRate = 18.0,
                    cgst = 900.0,
                    sgst = 900.0,
                    igst = 0.0,
                    total = 11800.0
                )
            )
        )
    }

    // Recalculate summary dynamically
    fun recalculateItem(item: TransactionItemDto, interstate: Boolean): TransactionItemDto {
        val gross = item.qty * item.rate
        val discAmount = (gross * item.discPercent) / 100.0
        val taxable = (gross - discAmount).coerceAtLeast(0.0)
        val taxRate = item.gstRate

        val cgst = if (!interstate) (taxable * (taxRate / 2.0)) / 100.0 else 0.0
        val sgst = if (!interstate) (taxable * (taxRate / 2.0)) / 100.0 else 0.0
        val igst = if (interstate) (taxable * taxRate) / 100.0 else 0.0
        val total = taxable + cgst + sgst + igst

        return item.copy(
            taxableValue = taxable,
            cgst = cgst,
            sgst = sgst,
            igst = igst,
            total = total
        )
    }

    val calculatedItems = remember(items, isInterstate) {
        items.map { recalculateItem(it, isInterstate) }
    }

    val totalTaxable = remember(calculatedItems) { calculatedItems.sumOf { it.taxableValue } }
    val totalCgst = remember(calculatedItems) { calculatedItems.sumOf { it.cgst } }
    val totalSgst = remember(calculatedItems) { calculatedItems.sumOf { it.sgst } }
    val totalIgst = remember(calculatedItems) { calculatedItems.sumOf { it.igst } }
    val rawGrandTotal = totalTaxable + totalCgst + totalSgst + totalIgst
    val grandTotalRounded = rawGrandTotal.roundToInt().toDouble()
    val roundOff = grandTotalRounded - rawGrandTotal

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
                        text = "${if (existingTransaction != null) "Edit" else "Create"} $transactionType Voucher",
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Black,
                        color = textDark
                    )
                    Text(
                        text = "Fill GST & item details below",
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

            HorizontalDivider(color = Color(0xFFF1F5F9))

            // 1. Doc Number & Date
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = docNumber,
                    onValueChange = { docNumber = it },
                    label = { Text("Doc / Invoice #") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
                OutlinedTextField(
                    value = docDate,
                    onValueChange = { docDate = it },
                    label = { Text("Date (YYYY-MM-DD)") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
            }

            // 2. Party Name with auto-picker
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                OutlinedTextField(
                    value = partyName,
                    onValueChange = { partyName = it },
                    label = { Text(if (transactionType == "Sales") "Customer Name *" else "Vendor / Payee Name *") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )

                // Quick party presets chips
                if (parties.isNotEmpty()) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        parties.take(3).forEach { p ->
                            Surface(
                                shape = RoundedCornerShape(8.dp),
                                color = Color(0xFFF8FAFC),
                                border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                                modifier = Modifier.clickable {
                                    partyName = p.name
                                    partyGstin = p.gstin
                                    partyPan = p.pan
                                    partyAddress = p.billingAddress
                                    partyPhone = p.phone
                                }
                            ) {
                                Text(
                                    text = p.name,
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = primaryIndigo,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                                )
                            }
                        }
                    }
                }
            }

            // GSTIN & Place of Supply
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = partyGstin,
                    onValueChange = { partyGstin = it },
                    label = { Text("GSTIN (Optional)") },
                    modifier = Modifier.weight(1.2f),
                    singleLine = true
                )
                OutlinedTextField(
                    value = placeOfSupply,
                    onValueChange = { placeOfSupply = it },
                    label = { Text("Place of Supply") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
            }

            // Intra-State vs Inter-State Switch
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFFF8FAFC), RoundedCornerShape(12.dp))
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = if (isInterstate) "Inter-State Supply (IGST)" else "Intra-State Supply (CGST + SGST)",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = textDark
                    )
                    Text(
                        text = if (isInterstate) "Single integrated tax applies" else "50/50 central & state tax split",
                        fontSize = 10.5.sp,
                        color = textMuted
                    )
                }
                Switch(
                    checked = isInterstate,
                    onCheckedChange = { isInterstate = it },
                    colors = SwitchDefaults.colors(checkedThumbColor = primaryIndigo, checkedTrackColor = primaryIndigo.copy(alpha = 0.5f))
                )
            }

            // ITC Tagging (for purchases)
            if (transactionType == "Purchase") {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("ITC Eligibility Category", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = textMuted)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        listOf("Inputs", "Input Services", "Capital Goods", "Ineligible").forEach { cat ->
                            val isSel = itcEligibility == cat
                            Surface(
                                shape = RoundedCornerShape(8.dp),
                                color = if (isSel) primaryIndigo else Color(0xFFF1F5F9),
                                modifier = Modifier.clickable { itcEligibility = cat }
                            ) {
                                Text(
                                    text = cat,
                                    fontSize = 10.5.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = if (isSel) Color.White else textDark,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp)
                                )
                            }
                        }
                    }
                }
            }

            // 3. Line Items Section
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Line Items & Services", fontSize = 13.sp, fontWeight = FontWeight.Black, color = textDark)
                Button(
                    onClick = {
                        items = items + TransactionItemDto(
                            description = "Additional Item / Service",
                            qty = 1.0,
                            unit = "PCS",
                            rate = 1000.0,
                            gstRate = 18.0
                        )
                    },
                    shape = RoundedCornerShape(8.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = primaryIndigo.copy(alpha = 0.12f)),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                    modifier = Modifier.height(30.dp)
                ) {
                    Icon(Icons.Default.Add, contentDescription = null, tint = primaryIndigo, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Add Item", fontSize = 11.sp, color = primaryIndigo, fontWeight = FontWeight.Bold)
                }
            }

            // Items List
            calculatedItems.forEachIndexed { index, item ->
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = Color(0xFFF8FAFC),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("Item #${index + 1}", fontSize = 11.sp, fontWeight = FontWeight.Black, color = textMuted)
                            if (items.size > 1) {
                                Icon(
                                    imageVector = Icons.Default.Delete,
                                    contentDescription = "Remove Item",
                                    tint = Color(0xFFDC2626),
                                    modifier = Modifier.size(16.dp).clickable {
                                        items = items.filterIndexed { i, _ -> i != index }
                                    }
                                )
                            }
                        }

                        OutlinedTextField(
                            value = item.description,
                            onValueChange = { newVal ->
                                items = items.toMutableList().also { it[index] = it[index].copy(description = newVal) }
                            },
                            label = { Text("Description") },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true
                        )

                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedTextField(
                                value = item.qty.toString(),
                                onValueChange = { newVal ->
                                    val q = newVal.toDoubleOrNull() ?: 1.0
                                    items = items.toMutableList().also { it[index] = it[index].copy(qty = q) }
                                },
                                label = { Text("Qty") },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                modifier = Modifier.weight(1f),
                                singleLine = true
                            )
                            OutlinedTextField(
                                value = item.rate.toString(),
                                onValueChange = { newVal ->
                                    val r = newVal.toDoubleOrNull() ?: 0.0
                                    items = items.toMutableList().also { it[index] = it[index].copy(rate = r) }
                                },
                                label = { Text("Rate (₹)") },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                modifier = Modifier.weight(1.5f),
                                singleLine = true
                            )
                            OutlinedTextField(
                                value = item.gstRate.toInt().toString(),
                                onValueChange = { newVal ->
                                    val g = newVal.toDoubleOrNull() ?: 18.0
                                    items = items.toMutableList().also { it[index] = it[index].copy(gstRate = g) }
                                },
                                label = { Text("GST %") },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                modifier = Modifier.weight(1f),
                                singleLine = true
                            )
                        }

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text("Taxable: ${IndianCurrencyFormatter.format(item.taxableValue)}", fontSize = 11.sp, color = textMuted)
                            Text("Total: ${IndianCurrencyFormatter.format(item.total)}", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = primaryIndigo)
                        }
                    }
                }
            }

            // 4. Totals Summary Card
            Surface(
                shape = RoundedCornerShape(14.dp),
                color = Color(0xFF0F172A),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Taxable Subtotal", color = Color(0xFF94A3B8), fontSize = 12.sp)
                        Text(IndianCurrencyFormatter.format(totalTaxable), color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                    if (!isInterstate) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("CGST Total", color = Color(0xFF94A3B8), fontSize = 12.sp)
                            Text(IndianCurrencyFormatter.format(totalCgst), color = Color.White, fontSize = 12.sp)
                        }
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("SGST Total", color = Color(0xFF94A3B8), fontSize = 12.sp)
                            Text(IndianCurrencyFormatter.format(totalSgst), color = Color.White, fontSize = 12.sp)
                        }
                    } else {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("IGST Total", color = Color(0xFF94A3B8), fontSize = 12.sp)
                            Text(IndianCurrencyFormatter.format(totalIgst), color = Color.White, fontSize = 12.sp)
                        }
                    }
                    HorizontalDivider(color = Color.White.copy(alpha = 0.15f))
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("GRAND TOTAL", color = Color.White, fontSize = 14.sp, fontWeight = FontWeight.Black)
                        Text(IndianCurrencyFormatter.format(grandTotalRounded), color = Color(0xFF818CF8), fontSize = 16.sp, fontWeight = FontWeight.Black)
                    }
                }
            }

            // Submit Button
            Button(
                onClick = {
                    if (partyName.isBlank()) {
                        Toast.makeText(context, "Please enter party / customer name", Toast.LENGTH_SHORT).show()
                        return@Button
                    }
                    val payload = TransactionDto(
                        id = existingTransaction?.id ?: "",
                        transactionType = transactionType,
                        docNumber = docNumber,
                        docDate = docDate,
                        dueDate = dueDate,
                        paymentMode = paymentMode,
                        paymentStatus = paymentStatus,
                        partyName = partyName,
                        partyGstin = partyGstin,
                        partyPan = partyPan,
                        partyAddress = partyAddress,
                        partyPhone = partyPhone,
                        placeOfSupply = placeOfSupply,
                        isInterstate = isInterstate,
                        itcEligibility = itcEligibility,
                        items = calculatedItems,
                        summary = TransactionSummaryDto(
                            totalTaxableValue = totalTaxable,
                            totalCgst = totalCgst,
                            totalSgst = totalSgst,
                            totalIgst = totalIgst,
                            roundOff = roundOff,
                            totalAmount = grandTotalRounded,
                            amountInWords = IndianCurrencyFormatter.numberToWords(grandTotalRounded)
                        )
                    )
                    onSubmit(payload)
                },
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = primaryIndigo),
                modifier = Modifier.fillMaxWidth().height(48.dp)
            ) {
                Icon(Icons.Default.Check, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = if (existingTransaction != null) "Update $transactionType Voucher" else "Save & Record $transactionType",
                    fontWeight = FontWeight.Black,
                    fontSize = 14.sp
                )
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}
