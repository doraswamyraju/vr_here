package com.sbr.vrherebms.ui.screens.customer.bookkeeping.dialogs

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.util.Base64
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import coil.compose.AsyncImage
import com.sbr.vrherebms.data.model.BankAccountDetailsDto
import com.sbr.vrherebms.data.model.CompanyDetailsDto
import java.io.ByteArrayOutputStream
import java.io.InputStream

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CompanySettingsBottomSheet(
    currentDetails: CompanyDetailsDto?,
    onDismiss: () -> Unit,
    onSubmit: (CompanyDetailsDto) -> Unit
) {
    val context = LocalContext.current
    val primaryIndigo = Color(0xFF4F46E5)
    val textDark = Color(0xFF0F172A)
    val textMuted = Color(0xFF64748B)

    var companyName by remember { mutableStateOf(currentDetails?.companyName ?: "") }
    var tradeName by remember { mutableStateOf(currentDetails?.tradeName ?: "") }
    var gstin by remember { mutableStateOf(currentDetails?.gstin ?: "") }
    var address by remember { mutableStateOf(currentDetails?.address ?: "") }
    var state by remember { mutableStateOf(currentDetails?.state?.ifEmpty { "Andhra Pradesh" } ?: "Andhra Pradesh") }
    var phone by remember { mutableStateOf(currentDetails?.phone ?: "") }
    var email by remember { mutableStateOf(currentDetails?.email ?: "") }
    var businessType by remember { mutableStateOf(currentDetails?.businessType?.ifEmpty { currentDetails?.companyType }?.ifEmpty { "Service" } ?: "Service") }
    var businessCategory by remember { mutableStateOf(currentDetails?.businessCategory?.ifEmpty { currentDetails?.companyCategory } ?: "") }
    var pincode by remember { mutableStateOf(currentDetails?.pincode ?: "") }
    var invoicePrefix by remember { mutableStateOf(currentDetails?.invoicePrefix?.ifEmpty { "INV-" } ?: "INV-") }
    var upiId by remember { mutableStateOf(currentDetails?.upiId ?: "") }

    // Media fields (Data URL / Image URL)
    var logoUrl by remember { mutableStateOf(currentDetails?.logo ?: "") }
    var signatureUrl by remember { mutableStateOf(currentDetails?.signature ?: "") }
    var qrCodeUrl by remember { mutableStateOf(currentDetails?.qrCode ?: "") }

    // Bank details
    var bankName by remember { mutableStateOf(currentDetails?.bankDetails?.bankName ?: "") }
    var accountName by remember { mutableStateOf(currentDetails?.bankDetails?.accountName ?: "") }
    var accountNumber by remember { mutableStateOf(currentDetails?.bankDetails?.accountNumber ?: "") }
    var ifscCode by remember { mutableStateOf(currentDetails?.bankDetails?.ifscCode ?: "") }

    var expandedBusinessType by remember { mutableStateOf(false) }
    var expandedState by remember { mutableStateOf(false) }

    fun uriToBase64(uri: Uri): String? {
        return try {
            val inputStream: InputStream? = context.contentResolver.openInputStream(uri)
            val bitmap = BitmapFactory.decodeStream(inputStream)
            val outputStream = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.JPEG, 75, outputStream)
            val byteArray = outputStream.toByteArray()
            "data:image/jpeg;base64," + Base64.encodeToString(byteArray, Base64.NO_WRAP)
        } catch (e: Exception) {
            null
        }
    }

    // Image pickers
    val logoPickerLauncher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) {
            val base64 = uriToBase64(uri)
            if (base64 != null) logoUrl = base64
        }
    }

    val signaturePickerLauncher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) {
            val base64 = uriToBase64(uri)
            if (base64 != null) signatureUrl = base64
        }
    }

    val qrPickerLauncher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) {
            val base64 = uriToBase64(uri)
            if (base64 != null) qrCodeUrl = base64
        }
    }

    val indianStates = listOf(
        "Andhra Pradesh", "Telangana", "Karnataka", "Tamil Nadu", "Maharashtra",
        "Delhi", "Gujarat", "Kerala", "Uttar Pradesh", "West Bengal", "Rajasthan",
        "Madhya Pradesh", "Punjab", "Haryana", "Bihar", "Odisha", "Assam", "Goa", "Uttarakhand", "Jharkhand"
    )

    val businessTypes = listOf(
        "Service", "Retail", "Manufacturing", "Distributor", "Private Limited", "Proprietorship", "LLP", "Partnership"
    )

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
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "Edit Profile & Business Details",
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Black,
                        color = textDark
                    )
                    Text(
                        text = "Configure legal corporate details, bank info & invoice branding",
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

            // Section 1: Logo & Branding Header Card
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = Color(0xFFF8FAFC),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(14.dp).fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(72.dp)
                            .background(Color.White, CircleShape)
                            .border(1.5.dp, Color(0xFFCBD5E1), CircleShape)
                            .clip(CircleShape)
                            .clickable { logoPickerLauncher.launch("image/*") },
                        contentAlignment = Alignment.Center
                    ) {
                        if (logoUrl.isNotEmpty()) {
                            AsyncImage(
                                model = logoUrl,
                                contentDescription = "Company Logo",
                                modifier = Modifier.fillMaxSize(),
                                contentScale = ContentScale.Crop
                            )
                        } else {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Icon(Icons.Default.Business, contentDescription = null, tint = Color(0xFF94A3B8), modifier = Modifier.size(24.dp))
                                Text("Upload", fontSize = 9.sp, fontWeight = FontWeight.Bold, color = Color(0xFF64748B))
                            }
                        }
                    }

                    Column(modifier = Modifier.weight(1f)) {
                        Text("Business Brand Logo", fontSize = 13.sp, fontWeight = FontWeight.Black, color = textDark)
                        Text("Appears at top of GST Invoices and vouchers", fontSize = 11.sp, color = textMuted)
                        Spacer(modifier = Modifier.height(6.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(
                                onClick = { logoPickerLauncher.launch("image/*") },
                                shape = RoundedCornerShape(8.dp),
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                                modifier = Modifier.height(30.dp)
                            ) {
                                Text(if (logoUrl.isEmpty()) "Choose Image" else "Change Logo", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                            }
                            if (logoUrl.isNotEmpty()) {
                                TextButton(
                                    onClick = { logoUrl = "" },
                                    contentPadding = PaddingValues(horizontal = 6.dp, vertical = 4.dp),
                                    modifier = Modifier.height(30.dp)
                                ) {
                                    Text("Remove", fontSize = 10.sp, color = Color(0xFFDC2626))
                                }
                            }
                        }
                    }
                }
            }

            // Invoice Prefix
            OutlinedTextField(
                value = invoicePrefix,
                onValueChange = { invoicePrefix = it },
                label = { Text("Invoice Number Prefix (e.g. INV-)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            // Section 2: Business Details
            Text("Business Information", fontSize = 13.sp, fontWeight = FontWeight.Black, color = textDark)

            OutlinedTextField(
                value = companyName,
                onValueChange = { companyName = it },
                label = { Text("Business Legal Name *") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = tradeName,
                    onValueChange = { tradeName = it },
                    label = { Text("Trade / Brand Name") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
                OutlinedTextField(
                    value = gstin,
                    onValueChange = { gstin = it.uppercase() },
                    label = { Text("GSTIN *") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
            }

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = phone,
                    onValueChange = { phone = it },
                    label = { Text("Contact Phone") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
                OutlinedTextField(
                    value = email,
                    onValueChange = { email = it },
                    label = { Text("Billing Email") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
            }

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                // Business Type Dropdown
                ExposedDropdownMenuBox(
                    expanded = expandedBusinessType,
                    onExpandedChange = { expandedBusinessType = !expandedBusinessType },
                    modifier = Modifier.weight(1f)
                ) {
                    OutlinedTextField(
                        value = businessType,
                        onValueChange = {},
                        readOnly = true,
                        label = { Text("Business Type") },
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expandedBusinessType) },
                        modifier = Modifier.menuAnchor().fillMaxWidth()
                    )
                    ExposedDropdownMenu(
                        expanded = expandedBusinessType,
                        onDismissRequest = { expandedBusinessType = false }
                    ) {
                        businessTypes.forEach { type ->
                            DropdownMenuItem(
                                text = { Text(type, fontSize = 12.sp) },
                                onClick = {
                                    businessType = type
                                    expandedBusinessType = false
                                }
                            )
                        }
                    }
                }

                OutlinedTextField(
                    value = businessCategory,
                    onValueChange = { businessCategory = it },
                    label = { Text("Category (e.g. IT)") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
            }

            // Section 3: Location & Jurisdiction
            Text("Location & Registered Address", fontSize = 13.sp, fontWeight = FontWeight.Black, color = textDark)

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                // State Dropdown
                ExposedDropdownMenuBox(
                    expanded = expandedState,
                    onExpandedChange = { expandedState = !expandedState },
                    modifier = Modifier.weight(1.3f)
                ) {
                    OutlinedTextField(
                        value = state,
                        onValueChange = {},
                        readOnly = true,
                        label = { Text("State *") },
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expandedState) },
                        modifier = Modifier.menuAnchor().fillMaxWidth()
                    )
                    ExposedDropdownMenu(
                        expanded = expandedState,
                        onDismissRequest = { expandedState = false }
                    ) {
                        indianStates.forEach { st ->
                            DropdownMenuItem(
                                text = { Text(st, fontSize = 12.sp) },
                                onClick = {
                                    state = st
                                    expandedState = false
                                }
                            )
                        }
                    }
                }

                OutlinedTextField(
                    value = pincode,
                    onValueChange = { pincode = it },
                    label = { Text("Pincode") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
            }

            OutlinedTextField(
                value = address,
                onValueChange = { address = it },
                label = { Text("Complete Office Address *") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 2,
                maxLines = 3
            )

            // Section 4: Bank Details for Invoicing
            HorizontalDivider(color = Color(0xFFF1F5F9))
            Text("Bank Account Details (For Invoicing)", fontSize = 13.sp, fontWeight = FontWeight.Black, color = textDark)

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = bankName,
                    onValueChange = { bankName = it },
                    label = { Text("Bank Name") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
                OutlinedTextField(
                    value = accountNumber,
                    onValueChange = { accountNumber = it },
                    label = { Text("Account Number") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
            }

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = ifscCode,
                    onValueChange = { ifscCode = it.uppercase() },
                    label = { Text("IFSC Code") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
                OutlinedTextField(
                    value = accountName,
                    onValueChange = { accountName = it },
                    label = { Text("A/c Holder Name") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
            }

            // Section 5: UPI, QR & Signature
            HorizontalDivider(color = Color(0xFFF1F5F9))
            Text("Payments & Signatures", fontSize = 13.sp, fontWeight = FontWeight.Black, color = textDark)

            OutlinedTextField(
                value = upiId,
                onValueChange = { upiId = it },
                label = { Text("UPI ID (e.g. business@hdfcbank)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                // QR Code
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = Color(0xFFF8FAFC),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                    modifier = Modifier.weight(1f).clickable { qrPickerLauncher.launch("image/*") }
                ) {
                    Column(
                        modifier = Modifier.padding(12.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        if (qrCodeUrl.isNotEmpty()) {
                            AsyncImage(
                                model = qrCodeUrl,
                                contentDescription = "Payment QR",
                                modifier = Modifier.size(54.dp),
                                contentScale = ContentScale.Fit
                            )
                            Text("Payment QR Attached", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFF047857))
                        } else {
                            Icon(Icons.Default.QrCode, contentDescription = null, tint = textMuted, modifier = Modifier.size(24.dp))
                            Spacer(modifier = Modifier.height(4.dp))
                            Text("Upload QR Image", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = textMuted)
                        }
                    }
                }

                // Signature
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = Color(0xFFF8FAFC),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                    modifier = Modifier.weight(1f).clickable { signaturePickerLauncher.launch("image/*") }
                ) {
                    Column(
                        modifier = Modifier.padding(12.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        if (signatureUrl.isNotEmpty()) {
                            AsyncImage(
                                model = signatureUrl,
                                contentDescription = "Signature",
                                modifier = Modifier.size(54.dp),
                                contentScale = ContentScale.Fit
                            )
                            Text("Signature Attached", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFF047857))
                        } else {
                            Icon(Icons.Default.Draw, contentDescription = null, tint = textMuted, modifier = Modifier.size(24.dp))
                            Spacer(modifier = Modifier.height(4.dp))
                            Text("Upload Signature", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = textMuted)
                        }
                    }
                }
            }

            // Submit Button
            Button(
                onClick = {
                    if (companyName.isBlank() || gstin.isBlank()) {
                        Toast.makeText(context, "Please enter Business Legal Name and GSTIN", Toast.LENGTH_SHORT).show()
                        return@Button
                    }
                    val updated = CompanyDetailsDto(
                        id = currentDetails?.id ?: "",
                        companyName = companyName.trim(),
                        tradeName = tradeName.trim(),
                        gstin = gstin.trim().uppercase(),
                        address = address.trim(),
                        state = state.trim(),
                        phone = phone.trim(),
                        email = email.trim(),
                        businessType = businessType.trim(),
                        companyType = businessType.trim(),
                        businessCategory = businessCategory.trim(),
                        companyCategory = businessCategory.trim(),
                        pincode = pincode.trim(),
                        invoicePrefix = invoicePrefix.trim(),
                        logo = logoUrl,
                        signature = signatureUrl,
                        qrCode = qrCodeUrl,
                        upiId = upiId.trim(),
                        bankDetails = BankAccountDetailsDto(
                            accountName = accountName.trim().ifBlank { companyName.trim() },
                            accountNumber = accountNumber.trim(),
                            ifscCode = ifscCode.trim().uppercase(),
                            bankName = bankName.trim()
                        )
                    )
                    onSubmit(updated)
                },
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = primaryIndigo),
                modifier = Modifier.fillMaxWidth().height(48.dp)
            ) {
                Icon(Icons.Default.Check, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Save Company & Bank Settings", fontWeight = FontWeight.Bold)
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}
