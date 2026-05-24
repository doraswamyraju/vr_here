package com.sbr.vrherebms.ui.screens.admin.modules

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel

data class ComplianceRecord(
    val id: String,
    val clientName: String,
    val taskName: String,
    val category: String,
    val dueDate: String,
    var status: String // 'Filed', 'Late', 'Missed', 'Pending'
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminComplianceScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var activeTab by remember { mutableStateOf("Dashboard") }
    var searchQuery by remember { mutableStateOf("") }
    var showNewCheckDialog by remember { mutableStateOf(false) }

    val categories = listOf("Dashboard", "GST", "MCA", "DIN KYC", "TDS/TCS", "Income Tax", "ESI", "PF", "PT", "Notices")

    // Seed mock records matching the exact look of compliance module
    var records by remember {
        mutableStateOf(
            listOf(
                ComplianceRecord("1", "Rajugari Ventures", "GSTR-1 Return Filing", "GST", "2026-06-11", "Pending"),
                ComplianceRecord("2", "Sri Navya", "SPICe+ Director DIN KYC", "DIN KYC", "2026-05-31", "Filed"),
                ComplianceRecord("3", "Gayatri Enterprises", "Contract Labour ESI Return", "ESI", "2026-06-15", "Late"),
                ComplianceRecord("4", "Blue Cat Solutions", "TDS Q4 Return Filing", "TDS/TCS", "2026-05-24", "Missed"),
                ComplianceRecord("5", "Mark & Co", "Income Tax ITR-6 Auditing", "Income Tax", "2026-07-31", "Pending"),
                ComplianceRecord("6", "Raju CA Corp", "MCA Form MGT-7 Filing", "MCA", "2026-09-30", "Filed")
            )
        )
    }

    val filteredRecords = remember(activeTab, searchQuery, records) {
        records.filter {
            val matchesTab = activeTab == "Dashboard" || it.category.equals(activeTab, ignoreCase = true)
            val matchesQuery = it.clientName.contains(searchQuery, ignoreCase = true) || it.taskName.contains(searchQuery, ignoreCase = true)
            matchesTab && matchesQuery
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF1F5F9))
    ) {
        // 1. Sleek Purple Command Header
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1B4B))
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Text(
                    text = "COMPLIANCE MANAGEMENT",
                    color = Color(0xFF38BDF8),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.ExtraBold,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Statutory Filing Ledger",
                    color = Color.White,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Track state tax filings, statutory MCA deadlines, and legal compliance audits across all clients.",
                    color = Color(0xFF94A3B8),
                    fontSize = 12.sp,
                    lineHeight = 16.sp
                )
            }
        }

        // 2. Category selection row
        LazyRow(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(categories) { cat ->
                val isSelected = activeTab == cat
                Box(
                    modifier = Modifier
                        .background(
                            if (isSelected) Color(0xFF4F46E5) else Color.White,
                            RoundedCornerShape(12.dp)
                        )
                        .border(
                            1.dp,
                            if (isSelected) Color.Transparent else Color(0xFFE2E8F0),
                            RoundedCornerShape(12.dp)
                        )
                        .clickable { activeTab = cat }
                        .padding(horizontal = 14.dp, vertical = 8.dp)
                ) {
                    Text(
                        text = cat,
                        color = if (isSelected) Color.White else Color(0xFF64748B),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Black
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // 3. Search and Actions bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = { Text("Search by client/task...", fontSize = 13.sp) },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = Color(0xFF64748B)) },
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = Color.White,
                    unfocusedContainerColor = Color.White,
                    focusedBorderColor = Color(0xFF4F46E5),
                    unfocusedBorderColor = Color(0xFFE2E8F0)
                ),
                singleLine = true
            )

            Button(
                onClick = { showNewCheckDialog = true },
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.height(52.dp)
            ) {
                Icon(Icons.Default.Add, contentDescription = null)
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 4. Filing Records List
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            items(filteredRecords) { r ->
                val statusColor = when (r.status) {
                    "Filed" -> Color(0xFF10B981)
                    "Late" -> Color(0xFFF59E0B)
                    "Missed" -> Color(0xFFEF4444)
                    else -> Color(0xFF3B82F6)
                }
                var expandedMenu by remember { mutableStateOf(false) }

                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFEEF2F6))
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = r.taskName,
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFF1E293B)
                                )
                                Text(
                                    text = "Client: ${r.clientName}",
                                    fontSize = 11.sp,
                                    color = Color(0xFF64748B),
                                    fontWeight = FontWeight.Medium
                                )
                            }

                            Box {
                                Box(
                                    modifier = Modifier
                                        .background(statusColor.copy(alpha = 0.1f), RoundedCornerShape(6.dp))
                                        .clickable { expandedMenu = true }
                                        .padding(horizontal = 10.dp, vertical = 4.dp)
                                ) {
                                    Text(
                                        text = r.status.uppercase(),
                                        color = statusColor,
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Black
                                    )
                                }

                                DropdownMenu(
                                    expanded = expandedMenu,
                                    onDismissRequest = { expandedMenu = false }
                                ) {
                                    listOf("Pending", "Filed", "Late", "Missed").forEach { opt ->
                                        DropdownMenuItem(
                                            text = { Text(opt) },
                                            onClick = {
                                                records = records.map { old ->
                                                    if (old.id == r.id) old.copy(status = opt) else old
                                                }
                                                Toast.makeText(context, "Status updated to $opt", Toast.LENGTH_SHORT).show()
                                                expandedMenu = false
                                            }
                                        )
                                    }
                                }
                            }
                        }

                        Spacer(modifier = Modifier.height(10.dp))
                        Divider(color = Color(0xFFF1F5F9))
                        Spacer(modifier = Modifier.height(10.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Icon(Icons.Default.CalendarToday, contentDescription = null, tint = Color(0xFF64748B), modifier = Modifier.size(12.dp))
                                Text(
                                    text = "Due: ${r.dueDate}",
                                    fontSize = 11.sp,
                                    color = Color(0xFF64748B),
                                    fontWeight = FontWeight.Bold
                                )
                            }

                            Box(
                                modifier = Modifier
                                    .background(Color(0xFFEFF6FF), RoundedCornerShape(6.dp))
                                    .padding(horizontal = 8.dp, vertical = 2.dp)
                            ) {
                                Text(
                                    text = r.category.uppercase(),
                                    color = Color(0xFF3B82F6),
                                    fontSize = 8.sp,
                                    fontWeight = FontWeight.Black
                                )
                            }
                        }
                    }
                }
            }

            if (filteredRecords.isEmpty()) {
                item {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 40.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "No compliance deadlines match filters.",
                            color = Color(0xFF64748B),
                            fontSize = 12.sp,
                            textAlign = TextAlign.Center
                        )
                    }
                }
            }
        }
    }

    // New filing registrar form modal
    if (showNewCheckDialog) {
        var clientName by remember { mutableStateOf("") }
        var taskName by remember { mutableStateOf("") }
        var cat by remember { mutableStateOf("GST") }
        var date by remember { mutableStateOf("2026-06-15") }

        Dialog(onDismissRequest = { showNewCheckDialog = false }) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(8.dp),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFF1F5F9))
            ) {
                Column(
                    modifier = Modifier.padding(24.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Text(
                        text = "Schedule Compliance Check",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFF1E293B)
                    )

                    OutlinedTextField(
                        value = clientName,
                        onValueChange = { clientName = it },
                        label = { Text("Client Name") },
                        modifier = Modifier.fillMaxWidth()
                    )

                    OutlinedTextField(
                        value = taskName,
                        onValueChange = { taskName = it },
                        label = { Text("Statutory Task / Return") },
                        modifier = Modifier.fillMaxWidth()
                    )

                    OutlinedTextField(
                        value = cat,
                        onValueChange = { cat = it },
                        label = { Text("Filing Category (e.g. GST, MCA)") },
                        modifier = Modifier.fillMaxWidth()
                    )

                    OutlinedTextField(
                        value = date,
                        onValueChange = { date = it },
                        label = { Text("Statutory Due Date (YYYY-MM-DD)") },
                        modifier = Modifier.fillMaxWidth()
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        TextButton(onClick = { showNewCheckDialog = false }) {
                            Text("Cancel", color = Color(0xFF64748B))
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Button(
                            onClick = {
                                if (clientName.isBlank() || taskName.isBlank()) {
                                    Toast.makeText(context, "All fields are required", Toast.LENGTH_SHORT).show()
                                    return@Button
                                }
                                val newRec = ComplianceRecord(
                                    id = (records.size + 1).toString(),
                                    clientName = clientName,
                                    taskName = taskName,
                                    category = cat,
                                    dueDate = date,
                                    status = "Pending"
                                )
                                records = records + newRec
                                Toast.makeText(context, "Compliance filing scheduled!", Toast.LENGTH_SHORT).show()
                                showNewCheckDialog = false
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF10B981))
                        ) {
                            Text("Add Filing", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }
    }
}
