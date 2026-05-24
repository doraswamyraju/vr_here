package com.sbr.vrherebms.ui.screens.partner

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.PartnerDashboardViewModel

@Composable
fun PartnerSettingsTab(viewModel: PartnerDashboardViewModel) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Account Settings",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF1E293B)
                )
                Text(
                    "Manage your professional identity and payout preferences.",
                    fontSize = 12.sp,
                    color = Color(0xFF64748B)
                )
            }
        }

        // Professional Identity Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(modifier = Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                        Icon(Icons.Default.Person, contentDescription = null, tint = Color(0xFF0F172A))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            "Professional Identity",
                            fontWeight = FontWeight.Black,
                            fontSize = 15.sp,
                            color = Color(0xFF1E293B)
                        )
                    }

                    OutlinedTextField(
                        value = viewModel.nameInput,
                        onValueChange = { viewModel.nameInput = it },
                        label = { Text("Full Name") },
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth()
                    )

                    OutlinedTextField(
                        value = viewModel.panCardInput,
                        onValueChange = { viewModel.panCardInput = it },
                        label = { Text("PAN Card Number") },
                        shape = RoundedCornerShape(14.dp),
                        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters),
                        modifier = Modifier.fillMaxWidth()
                    )

                    // Read-only email and phone
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(Color(0xFFF1F5F9), RoundedCornerShape(14.dp))
                            .padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                            Text("Email ID", fontSize = 10.sp, color = Color(0xFF64748B), fontWeight = FontWeight.Bold)
                            Text(viewModel.profile?.email ?: "", fontSize = 11.sp, color = Color(0xFF334155), fontWeight = FontWeight.Black)
                        }
                        Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                            Text("Referral Code (Phone)", fontSize = 10.sp, color = Color(0xFF64748B), fontWeight = FontWeight.Bold)
                            Text(viewModel.profile?.phone ?: "", fontSize = 11.sp, color = Color(0xFF334155), fontWeight = FontWeight.Black)
                        }
                    }
                }
            }
        }

        // Payout Destination Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(modifier = Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                        Icon(Icons.Default.CreditCard, contentDescription = null, tint = Color(0xFF4F46E5))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            "Payout Destination",
                            fontWeight = FontWeight.Black,
                            fontSize = 15.sp,
                            color = Color(0xFF1E293B)
                        )
                    }

                    OutlinedTextField(
                        value = viewModel.bankAccountNameInput,
                        onValueChange = { viewModel.bankAccountNameInput = it },
                        label = { Text("Account Holder Name") },
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth()
                    )

                    OutlinedTextField(
                        value = viewModel.bankNameInput,
                        onValueChange = { viewModel.bankNameInput = it },
                        label = { Text("Bank Name") },
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth()
                    )

                    OutlinedTextField(
                        value = viewModel.bankAccountNumberInput,
                        onValueChange = { viewModel.bankAccountNumberInput = it },
                        label = { Text("Account Number") },
                        shape = RoundedCornerShape(14.dp),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.fillMaxWidth()
                    )

                    OutlinedTextField(
                        value = viewModel.bankIfscCodeInput,
                        onValueChange = { viewModel.bankIfscCodeInput = it },
                        label = { Text("IFSC Code") },
                        shape = RoundedCornerShape(14.dp),
                        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters),
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        }

        // Submit Button
        item {
            Button(
                onClick = { viewModel.updateProfile() },
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF0F172A)),
                shape = RoundedCornerShape(16.dp),
                enabled = !viewModel.isSavingProfile,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp)
            ) {
                if (viewModel.isSavingProfile) {
                    CircularProgressIndicator(color = Color.White, modifier = Modifier.size(24.dp))
                } else {
                    Text("Save Payout Preference", fontWeight = FontWeight.Black, fontSize = 14.sp)
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(60.dp))
        }
    }
}
