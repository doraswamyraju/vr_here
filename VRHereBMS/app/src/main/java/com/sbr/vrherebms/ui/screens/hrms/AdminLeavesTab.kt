package com.sbr.vrherebms.ui.screens.hrms

import androidx.compose.foundation.background
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
import com.sbr.vrherebms.data.model.LeaveResponse
import com.sbr.vrherebms.viewmodel.HrmsViewModel

@Composable
fun AdminLeavesTab(viewModel: HrmsViewModel) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Text("Review Leave Applications", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
        }

        val pendingList = viewModel.adminLeaves.filter { it.status == "Pending" }
        val processedList = viewModel.adminLeaves.filter { it.status != "Pending" }

        item {
            Text("Pending Requests (${pendingList.size})", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFFF59E0B))
        }

        if (pendingList.isEmpty()) {
            item {
                Text("No pending requests.", fontSize = 12.sp, color = Color.Gray, modifier = Modifier.padding(start = 8.dp))
            }
        } else {
            items(pendingList) { leave ->
                AdminLeaveActionCard(leave, viewModel)
            }
        }

        item {
            Spacer(modifier = Modifier.height(8.dp))
            Text("Processed Requests History (${processedList.size})", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF475569))
        }

        if (processedList.isEmpty()) {
            item {
                Text("No previous requests processed.", fontSize = 12.sp, color = Color.Gray, modifier = Modifier.padding(start = 8.dp))
            }
        } else {
            items(processedList) { leave ->
                LeaveHistoryCard(leave)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminLeaveActionCard(leave: LeaveResponse, viewModel: HrmsViewModel) {
    var remarks by remember { mutableStateOf("") }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .background(Color(0xFFEEF2FF), RoundedCornerShape(20.dp)),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = leave.employee?.name?.firstOrNull()?.toString()?.uppercase() ?: "E",
                        fontWeight = FontWeight.Black,
                        color = Color(0xFF4F46E5)
                    )
                }

                Column(modifier = Modifier.weight(1f)) {
                    Text(leave.employee?.name ?: "Unknown Staff", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                    Text(leave.employee?.email ?: "", fontSize = 11.sp, color = Color.Gray)
                }
            }

            HorizontalDivider(color = Color(0xFFF1F5F9))

            Text("Duration: ${leave.startDate.take(10)} to ${leave.endDate.take(10)}", fontSize = 12.sp, color = Color.Gray)
            Text("Reason: ${leave.reason}", fontSize = 12.sp, color = Color(0xFF475569))

            OutlinedTextField(
                value = remarks,
                onValueChange = { remarks = it },
                label = { Text("Approval Remarks (Optional)") },
                modifier = Modifier.fillMaxWidth(),
                textStyle = MaterialTheme.typography.bodySmall
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Button(
                    onClick = { viewModel.approveLeave(leave.id, "Approved", remarks) },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10B981)),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text("Approve", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                }

                Button(
                    onClick = { viewModel.approveLeave(leave.id, "Rejected", remarks) },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFEF4444)),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text("Reject", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                }
            }
        }
    }
}
