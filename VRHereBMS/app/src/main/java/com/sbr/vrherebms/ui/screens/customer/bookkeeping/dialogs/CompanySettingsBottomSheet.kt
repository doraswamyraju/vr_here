package com.sbr.vrherebms.ui.screens.customer.bookkeeping.dialogs

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.BankAccountDetailsDto
import com.sbr.vrherebms.data.model.CompanyDetailsDto

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
    var state by remember { mutableStateOf(currentDetails?.state ?: "Andhra Pradesh") }
    var phone by remember { mutableStateOf(currentDetails?.phone ?: "") }
    var email by remember { mutableStateOf(currentDetails?.email ?: "") }
    var upiId by remember { mutableStateOf(currentDetails?.upiId ?: "") }

    // Bank details
    var bankName by remember { mutableStateOf(currentDetails?.bankDetails?.bankName ?: "") }
    var accountName by remember { mutableStateOf(currentDetails?.bankDetails?.accountName ?: "") }
    var accountNumber by remember { mutableStateOf(currentDetails?.bankDetails?.accountNumber ?: "") }
    var ifscCode by remember { mutableStateOf(currentDetails?.bankDetails?.ifscCode ?: "") }

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
                        text = "Company & Bank Settings",
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Black,
                        color = textDark
                    )
                    Text(
                        text = "Details rendered on generated Tax Invoices",
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
                    value = gstin,
                    onValueChange = { gstin = it },
                    label = { Text("GSTIN *") },
                    modifier = Modifier.weight(1.2f),
                    singleLine = true
                )
                OutlinedTextField(
                    value = state,
                    onValueChange = { state = it },
                    label = { Text("State") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
            }

            OutlinedTextField(
                value = address,
                onValueChange = { address = it },
                label = { Text("Registered Address") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

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
                    modifier = Modifier.weight(1.2f),
                    singleLine = true
                )
            }

            HorizontalDivider(color = Color(0xFFF1F5F9))
            Text("Bank & UPI Collection Setup", fontSize = 13.sp, fontWeight = FontWeight.Black, color = textDark)

            OutlinedTextField(
                value = upiId,
                onValueChange = { upiId = it },
                label = { Text("UPI ID (For Invoice QR Code)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = bankName,
                    onValueChange = { bankName = it },
                    label = { Text("Bank Name") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
                OutlinedTextField(
                    value = ifscCode,
                    onValueChange = { ifscCode = it },
                    label = { Text("IFSC Code") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
            }

            OutlinedTextField(
                value = accountNumber,
                onValueChange = { accountNumber = it },
                label = { Text("Account Number") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            Button(
                onClick = {
                    if (companyName.isBlank() || gstin.isBlank()) {
                        Toast.makeText(context, "Please enter company name and GSTIN", Toast.LENGTH_SHORT).show()
                        return@Button
                    }
                    val updated = CompanyDetailsDto(
                        id = currentDetails?.id ?: "",
                        companyName = companyName,
                        tradeName = tradeName,
                        gstin = gstin,
                        address = address,
                        state = state,
                        phone = phone,
                        email = email,
                        upiId = upiId,
                        bankDetails = BankAccountDetailsDto(
                            accountName = accountName.ifBlank { companyName },
                            accountNumber = accountNumber,
                            ifscCode = ifscCode,
                            bankName = bankName
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
                Text("Save Company Settings", fontWeight = FontWeight.Bold)
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}
