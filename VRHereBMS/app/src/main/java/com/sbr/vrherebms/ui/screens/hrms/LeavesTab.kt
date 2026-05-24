package com.sbr.vrherebms.ui.screens.hrms

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.HrmsViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LeavesTab(viewModel: HrmsViewModel) {
    var startDate by remember { mutableStateOf("") }
    var endDate by remember { mutableStateOf("") }
    var leaveType by remember { mutableStateOf("Casual") }
    var reason by remember { mutableStateOf("") }
    var expanded by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Balances summary card
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // Approved metric
                Card(
                    modifier = Modifier.weight(1f),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFECFDF5)),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text("Approved", fontSize = 11.sp, color = Color(0xFF10B981), fontWeight = FontWeight.Bold)
                        Text(
                            text = viewModel.leaves.count { it.status == "Approved" }.toString(),
                            fontSize = 28.sp,
                            fontWeight = FontWeight.Black,
                            color = Color(0xFF065F46)
                        )
                    }
                }

                // Pending metric
                Card(
                    modifier = Modifier.weight(1f),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFFFFBEB)),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text("Pending", fontSize = 11.sp, color = Color(0xFFF59E0B), fontWeight = FontWeight.Bold)
                        Text(
                            text = viewModel.leaves.count { it.status == "Pending" }.toString(),
                            fontSize = 28.sp,
                            fontWeight = FontWeight.Black,
                            color = Color(0xFF92400E)
                        )
                    }
                }
            }
        }

        // Leave Submission Form
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Apply for Leave", fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))

                    // Leave Type Dropdown
                    Box {
                        OutlinedTextField(
                            value = leaveType,
                            onValueChange = {},
                            readOnly = true,
                            label = { Text("Leave Type") },
                            modifier = Modifier.fillMaxWidth(),
                            trailingIcon = {
                                Text(
                                    text = "▼",
                                    modifier = Modifier.clickable { expanded = true }.padding(8.dp),
                                    fontSize = 12.sp
                                )
                            }
                        )
                        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                            listOf("Casual", "Sick", "Paid", "Unpaid").forEach { type ->
                                DropdownMenuItem(
                                    text = { Text(type) },
                                    onClick = {
                                        leaveType = type
                                        expanded = false
                                    }
                                )
                            }
                        }
                    }

                    // Start & End date (simple input layout for rapid deployment)
                    OutlinedTextField(
                        value = startDate,
                        onValueChange = { startDate = it },
                        label = { Text("Start Date (YYYY-MM-DD)") },
                        modifier = Modifier.fillMaxWidth()
                    )

                    OutlinedTextField(
                        value = endDate,
                        onValueChange = { endDate = it },
                        label = { Text("End Date (YYYY-MM-DD)") },
                        modifier = Modifier.fillMaxWidth()
                    )

                    OutlinedTextField(
                        value = reason,
                        onValueChange = { reason = it },
                        label = { Text("Reason for leave") },
                        modifier = Modifier.fillMaxWidth(),
                        maxLines = 3
                    )

                    Button(
                        onClick = {
                            if (startDate.isNotEmpty() && endDate.isNotEmpty() && reason.isNotEmpty()) {
                                viewModel.applyLeave(startDate, endDate, leaveType, reason)
                                startDate = ""
                                endDate = ""
                                reason = ""
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text("Submit Request", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        // Leave application logs list
        item {
            Text("My Leave Applications", fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
        }

        if (viewModel.leaves.isEmpty()) {
            item {
                Text("No previous requests submitted", fontSize = 13.sp, color = Color.Gray)
            }
        } else {
            items(viewModel.leaves) { leave ->
                LeaveHistoryCard(leave)
            }
        }
    }
}
