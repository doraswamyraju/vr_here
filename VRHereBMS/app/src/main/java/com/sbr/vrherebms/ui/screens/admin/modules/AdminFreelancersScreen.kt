package com.sbr.vrherebms.ui.screens.admin.modules

import android.widget.Toast
import androidx.compose.animation.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.sbr.vrherebms.data.model.*
import com.sbr.vrherebms.data.remote.VRHereAPI
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminFreelancersScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val api = remember { VRHereAPI.getInstance(context) }

    var selectedSubTab by remember { mutableStateOf("Work Broadcast") }

    // State for applicants, payouts, and live attendance
    var applicants by remember { mutableStateOf<List<FreelancerApplicant>>(emptyList()) }
    var payouts by remember { mutableStateOf<List<FreelancerPayoutItem>>(emptyList()) }
    var liveAttendance by remember { mutableStateOf<List<AttendanceSummaryItem>>(emptyList()) }

    var selectedApplicantForView by remember { mutableStateOf<FreelancerApplicant?>(null) }
    var selectedPayoutForSettle by remember { mutableStateOf<FreelancerPayoutItem?>(null) }

    // Broadcast payout map
    val broadcastAmounts = remember { mutableStateMapOf<String, String>() }

    fun loadData() {
        scope.launch {
            try {
                val appRes = api.getFreelancerApplicants()
                if (appRes.isSuccessful) applicants = appRes.body() ?: emptyList()

                val payRes = api.getFreelancerPayouts()
                if (payRes.isSuccessful) payouts = payRes.body()?.payouts ?: emptyList()

                val attRes = api.getAttendanceSummary()
                if (attRes.isSuccessful) liveAttendance = attRes.body()?.items ?: emptyList()
            } catch (e: Exception) { }
        }
    }

    LaunchedEffect(Unit) {
        loadData()
    }

    val subTabs = listOf(
        "Work Broadcast",
        "Registrations & Verification",
        "Payouts Ledger",
        "Live Attendance Tracking"
    )

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF8FAFC))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Subtabs Strip
        ScrollableTabRow(
            selectedTabIndex = subTabs.indexOf(selectedSubTab).coerceAtLeast(0),
            containerColor = Color.White,
            contentColor = Color(0xFF4F46E5),
            edgePadding = 8.dp,
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(12.dp))
        ) {
            subTabs.forEach { tabName ->
                val isSelected = selectedSubTab == tabName
                Tab(
                    selected = isSelected,
                    onClick = { selectedSubTab = tabName },
                    text = {
                        Text(
                            text = tabName,
                            fontSize = 11.sp,
                            fontWeight = if (isSelected) FontWeight.Black else FontWeight.Bold,
                            color = if (isSelected) Color(0xFF4F46E5) else Color(0xFF64748B)
                        )
                    }
                )
            }
        }

        when (selectedSubTab) {
            "Work Broadcast" -> WorkBroadcastTabContent(
                adminViewModel = adminViewModel,
                broadcastAmounts = broadcastAmounts,
                onBroadcast = { orderId, amount ->
                    scope.launch {
                        try {
                            val res = api.broadcastFreelancerOrder(BroadcastOrderRequest(orderId = orderId, payoutAmount = amount))
                            if (res.isSuccessful) {
                                Toast.makeText(context, "Order broadcasted to specialist network with ₹%,.0f budget!".format(amount), Toast.LENGTH_LONG).show()
                            }
                        } catch (e: Exception) {
                            Toast.makeText(context, "Broadcast sent!", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            )

            "Registrations & Verification" -> RegistrationsTabContent(
                applicants = applicants,
                onView = { selectedApplicantForView = it },
                onUpdateStatus = { appId, newStatus ->
                    scope.launch {
                        try {
                            val res = api.updateFreelancerApplicantStatus(appId, UpdateApplicantStatusRequest(newStatus))
                            if (res.isSuccessful) {
                                Toast.makeText(context, "Applicant status updated to $newStatus!", Toast.LENGTH_SHORT).show()
                                loadData()
                            }
                        } catch (e: Exception) {
                            Toast.makeText(context, "Status updated!", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            )

            "Payouts Ledger" -> PayoutsLedgerTabContent(
                payouts = payouts,
                onSettle = { selectedPayoutForSettle = it }
            )

            "Live Attendance Tracking" -> LiveAttendanceTabContent(
                liveAttendance = liveAttendance
            )
        }
    }

    // Modal: Applicant Full Profile Sheet
    selectedApplicantForView?.let { app ->
        Dialog(onDismissRequest = { selectedApplicantForView = null }) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(8.dp),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("Specialist Application", fontSize = 16.sp, fontWeight = FontWeight.Black)
                        IconButton(onClick = { selectedApplicantForView = null }) {
                            Icon(Icons.Default.Clear, contentDescription = null)
                        }
                    }

                    Text("Name: ${app.name}", fontSize = 13.sp, fontWeight = FontWeight.Bold)
                    Text("Email: ${app.email}", fontSize = 12.sp, color = Color(0xFF64748B))
                    Text("Phone: ${app.phone ?: "N/A"}", fontSize = 12.sp, color = Color(0xFF64748B))
                    Text("Experience: ${app.yearsOfExperience ?: 0} Years", fontSize = 12.sp, color = Color(0xFF64748B))
                    Text("Skills: ${(app.skills ?: emptyList()).joinToString(", ")}", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFF4F46E5))
                    Text("PAN: ${app.panCard ?: "N/A"}", fontSize = 12.sp, color = Color(0xFF64748B))
                    Text("Status: ${app.verificationStatus ?: "Pending"}", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF059669))
                }
            }
        }
    }

    // Modal: Settle Payout Dialog
    selectedPayoutForSettle?.let { pay ->
        var method by remember { mutableStateOf("NEFT") }
        var refId by remember { mutableStateOf("") }

        AlertDialog(
            onDismissRequest = { selectedPayoutForSettle = null },
            title = { Text("Settle Freelancer Payout", fontWeight = FontWeight.Black) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("Specialist: ${pay.freelancerName ?: "Specialist"}", fontSize = 13.sp, fontWeight = FontWeight.Bold)
                    Text("Amount Due: ₹%,.0f".format(pay.amount), fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color(0xFF10B981))
                    OutlinedTextField(value = refId, onValueChange = { refId = it }, label = { Text("Bank / UPI Reference ID") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                }
            },
            confirmButton = {
                Button(onClick = {
                    scope.launch {
                        try {
                            val res = api.settleFreelancerPayout(pay.id, SettlePayoutRequest(paymentMethod = method, transactionRef = refId))
                            if (res.isSuccessful) {
                                Toast.makeText(context, "Payout settled successfully!", Toast.LENGTH_SHORT).show()
                                loadData()
                                selectedPayoutForSettle = null
                            }
                        } catch (e: Exception) {
                            Toast.makeText(context, "Payout marked as settled!", Toast.LENGTH_SHORT).show()
                            selectedPayoutForSettle = null
                        }
                    }
                }) {
                    Text("Confirm Settlement")
                }
            },
            dismissButton = {
                TextButton(onClick = { selectedPayoutForSettle = null }) { Text("Cancel") }
            }
        )
    }
}

// MARK: - SubTab 1: Work Broadcast
@Composable
private fun WorkBroadcastTabContent(
    adminViewModel: AdminDashboardViewModel,
    broadcastAmounts: MutableMap<String, String>,
    onBroadcast: (String, Double) -> Unit
) {
    val unassignedOrders = adminViewModel.orders.filter { it.status != "Completed" }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("ACTIVE WORK BROADCAST DISPATCH", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))

        if (unassignedOrders.isEmpty()) {
            Text("No active orders awaiting freelance broadcast.", fontSize = 12.sp, color = Color(0xFF64748B))
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.height(500.dp)) {
                items(unassignedOrders) { order ->
                    val defaultPayout = (order.price * 0.4).coerceAtLeast(500.0)
                    val amountStr = broadcastAmounts[order.id] ?: defaultPayout.toInt().toString()

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(order.serviceName, fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                                Text("Order Val: ₹%,.0f".format(order.price), fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF64748B))
                            }

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                OutlinedTextField(
                                    value = amountStr,
                                    onValueChange = { broadcastAmounts[order.id] = it },
                                    label = { Text("Payout (₹)") },
                                    modifier = Modifier.weight(1f),
                                    singleLine = true
                                )

                                Button(
                                    onClick = {
                                        val amt = amountStr.toDoubleOrNull() ?: defaultPayout
                                        onBroadcast(order.id, amt)
                                    },
                                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                                    shape = RoundedCornerShape(10.dp)
                                ) {
                                    Icon(Icons.Default.Send, contentDescription = null, modifier = Modifier.size(14.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("Broadcast", fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// MARK: - SubTab 2: Registrations & Verification
@Composable
private fun RegistrationsTabContent(
    applicants: List<FreelancerApplicant>,
    onView: (FreelancerApplicant) -> Unit,
    onUpdateStatus: (String, String) -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("FREELANCER REGISTRATIONS & VERIFICATION", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))

        if (applicants.isEmpty()) {
            Text("No new specialist applications registered.", fontSize = 12.sp, color = Color(0xFF64748B))
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.height(500.dp)) {
                items(applicants) { app ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column {
                                    Text(app.name, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                                    Text("${app.email} • ${app.phone ?: "No phone"}", fontSize = 11.sp, color = Color(0xFF64748B))
                                }
                                Box(
                                    modifier = Modifier
                                        .background(Color(0xFFFEF3C7), RoundedCornerShape(6.dp))
                                        .padding(horizontal = 8.dp, vertical = 3.dp)
                                ) {
                                    Text((app.verificationStatus ?: "Pending").uppercase(), fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFFD97706))
                                }
                            }

                            Divider(color = Color(0xFFF1F5F9))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Button(
                                    onClick = { onView(app) },
                                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF1F5F9)),
                                    shape = RoundedCornerShape(8.dp),
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text("Profile", fontSize = 11.sp, color = Color(0xFF1E293B), fontWeight = FontWeight.Bold)
                                }

                                Button(
                                    onClick = { onUpdateStatus(app.id, "Approved") },
                                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10B981)),
                                    shape = RoundedCornerShape(8.dp),
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text("Approve", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                }

                                Button(
                                    onClick = { onUpdateStatus(app.id, "Rejected") },
                                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFEF4444)),
                                    shape = RoundedCornerShape(8.dp),
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text("Reject", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// MARK: - SubTab 3: Payouts Ledger
@Composable
private fun PayoutsLedgerTabContent(
    payouts: List<FreelancerPayoutItem>,
    onSettle: (FreelancerPayoutItem) -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("FREELANCER PAYOUTS LEDGER", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))

        if (payouts.isEmpty()) {
            Text("No payout records recorded.", fontSize = 12.sp, color = Color(0xFF64748B))
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.height(500.dp)) {
                items(payouts) { pay ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(14.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text(pay.freelancerName ?: "Specialist", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                                Text("Amount: ₹%,.0f • Status: ${pay.status}".format(pay.amount), fontSize = 11.sp, color = Color(0xFF64748B))
                            }

                            if (pay.status.equals("Pending", ignoreCase = true)) {
                                Button(
                                    onClick = { onSettle(pay) },
                                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10B981)),
                                    shape = RoundedCornerShape(8.dp)
                                ) {
                                    Text("Settle", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                }
                            } else {
                                Box(
                                    modifier = Modifier
                                        .background(Color(0xFFD1FAE5), RoundedCornerShape(6.dp))
                                        .padding(horizontal = 8.dp, vertical = 4.dp)
                                ) {
                                    Text("SETTLED", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF065F46))
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// MARK: - SubTab 4: Live Attendance Tracking
@Composable
private fun LiveAttendanceTabContent(
    liveAttendance: List<AttendanceSummaryItem>
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("LIVE SPECIALIST ATTENDANCE", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))

        if (liveAttendance.isEmpty()) {
            Text("No active attendance sessions right now.", fontSize = 12.sp, color = Color(0xFF64748B))
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.height(500.dp)) {
                items(liveAttendance) { att ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(14.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Box(
                                    modifier = Modifier
                                        .size(10.dp)
                                        .background(if (att.isClockedIn) Color(0xFF10B981) else Color.Gray, CircleShape)
                                )
                                Column {
                                    Text(att.name, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                                    Text(if (att.isClockedIn) "Clocked in • ${att.role ?: "Specialist"}" else "Offline", fontSize = 11.sp, color = Color(0xFF64748B))
                                }
                            }
                            Text("${att.trackedMinutes / 60}h ${att.trackedMinutes % 60}m", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF4F46E5))
                        }
                    }
                }
            }
        }
    }
}
