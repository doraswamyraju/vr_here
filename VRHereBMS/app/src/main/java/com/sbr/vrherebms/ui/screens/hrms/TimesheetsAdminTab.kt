package com.sbr.vrherebms.ui.screens.hrms

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
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
import com.sbr.vrherebms.viewmodel.HrmsViewModel

data class ShiftLogItem(
    val id: String,
    val employeeName: String,
    val role: String,
    val date: String,
    val totalHours: Double,
    val breakMinutes: Int,
    var status: String // 'Approved', 'Pending Review', 'Rejected'
)

@Composable
fun TimesheetsAdminTab(
    viewModel: HrmsViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var shiftLogs by remember {
        mutableStateOf(
            listOf(
                ShiftLogItem("1", "Raju Meesala", "Senior Associate CA", "Mon - Fri, Current Week", 42.5, 180, "Pending Review"),
                ShiftLogItem("2", "Vikram Varma", "Legal Specialist", "Mon - Fri, Current Week", 40.0, 150, "Approved"),
                ShiftLogItem("3", "Kiran Reddy", "Tax Consultant", "Mon - Fri, Current Week", 38.5, 200, "Pending Review"),
                ShiftLogItem("4", "Suresh Sharma", "Compliance Officer", "Mon - Fri, Current Week", 44.0, 160, "Approved")
            )
        )
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF8FAFC)),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Summary row
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Card(
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("Total Logged", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B))
                    Spacer(modifier = Modifier.height(2.dp))
                    Text("165.0 hrs", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                }
            }

            Card(
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("Pending Review", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B))
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        "${shiftLogs.count { it.status == "Pending Review" }} timesheets",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFFD97706)
                    )
                }
            }

            Card(
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("Approved", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B))
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        "${shiftLogs.count { it.status == "Approved" }} timesheets",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFF059669)
                    )
                }
            }
        }

        // Timesheets List
        LazyColumn(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = PaddingValues(bottom = 90.dp)
        ) {
            items(shiftLogs) { log ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(38.dp)
                                        .background(Color(0xFFEEF2FF), CircleShape),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        text = log.employeeName.take(1).uppercase(),
                                        fontWeight = FontWeight.Black,
                                        color = Color(0xFF4F46E5),
                                        fontSize = 14.sp
                                    )
                                }
                                Column {
                                    Text(text = log.employeeName, fontWeight = FontWeight.Black, fontSize = 13.sp, color = Color(0xFF0F172A))
                                    Text(text = "${log.role} • ${log.date}", fontSize = 11.sp, color = Color(0xFF64748B))
                                }
                            }

                            Box(
                                modifier = Modifier
                                    .background(
                                        if (log.status == "Approved") Color(0xFFDCFCE7) else Color(0xFFFEF3C7),
                                        RoundedCornerShape(6.dp)
                                    )
                                    .padding(horizontal = 8.dp, vertical = 3.dp)
                                ) {
                                Text(
                                    text = log.status.uppercase(),
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Black,
                                    color = if (log.status == "Approved") Color(0xFF16A34A) else Color(0xFFD97706)
                                )
                            }
                        }

                        Divider(color = Color(0xFFF8FAFC))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                                Column {
                                    Text("Logged Hours", fontSize = 9.sp, color = Color(0xFF94A3B8))
                                    Text("${log.totalHours} hrs", fontSize = 12.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                }
                                Column {
                                    Text("Total Breaks", fontSize = 9.sp, color = Color(0xFF94A3B8))
                                    Text("${log.breakMinutes} mins", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFF64748B))
                                }
                            }

                            if (log.status == "Pending Review") {
                                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                    Button(
                                        onClick = {
                                            shiftLogs = shiftLogs.map { if (it.id == log.id) it.copy(status = "Approved") else it }
                                            Toast.makeText(context, "Timesheet approved for ${log.employeeName}", Toast.LENGTH_SHORT).show()
                                        },
                                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF059669)),
                                        shape = RoundedCornerShape(8.dp),
                                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 5.dp)
                                    ) {
                                        Text("Approve", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                    }

                                    Button(
                                        onClick = {
                                            shiftLogs = shiftLogs.map { if (it.id == log.id) it.copy(status = "Rejected") else it }
                                            Toast.makeText(context, "Timesheet rejected", Toast.LENGTH_SHORT).show()
                                        },
                                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                                        shape = RoundedCornerShape(8.dp),
                                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 5.dp)
                                    ) {
                                        Text("Reject", fontSize = 10.sp, fontWeight = FontWeight.Bold)
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
