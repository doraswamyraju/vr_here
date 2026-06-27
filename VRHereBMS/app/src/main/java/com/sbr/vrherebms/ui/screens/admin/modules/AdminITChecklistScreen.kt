package com.sbr.vrherebms.ui.screens.admin.modules

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel

data class MockAssessment(
    val id: String,
    val clientName: String,
    val pan: String,
    val financialYear: String,
    val assessmentYear: String,
    val status: String
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminITChecklistScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    var searchQuery by remember { mutableStateOf("") }

    val assessments = remember {
        listOf(
            MockAssessment("1", "Kalyan Chakravarthy", "ABCDE1234F", "2025-26", "2026-27", "Approved"),
            MockAssessment("2", "Dora Raju Corp", "XYZAB5678C", "2025-26", "2026-27", "Pending"),
            MockAssessment("3", "Chandra & Co", "QWERP9876D", "2024-25", "2025-26", "In Progress"),
            MockAssessment("4", "Suneetha Ram", "LKJHG4321A", "2025-26", "2026-27", "Rejected")
        )
    }

    val filtered = remember(searchQuery) {
        assessments.filter {
            it.clientName.contains(searchQuery, ignoreCase = true) ||
                    it.pan.contains(searchQuery, ignoreCase = true)
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF1F5F9))
            .padding(16.dp)
    ) {
        // Search bar
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            placeholder = { Text("Search by client name or PAN...", fontSize = 14.sp) },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = "Search", tint = Color(0xFF64748B)) },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            singleLine = true
        )

        Spacer(modifier = Modifier.height(16.dp))

        LazyColumn(
            verticalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier.fillMaxSize()
        ) {
            items(filtered) { item ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = item.clientName,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF1E293B)
                            )
                            
                            val bg = when(item.status) {
                                "Approved" -> Color(0xFFECFDF5)
                                "Rejected" -> Color(0xFFFEF2F2)
                                else -> Color(0xFFFFF7ED)
                            }
                            val textCol = when(item.status) {
                                "Approved" -> Color(0xFF10B981)
                                "Rejected" -> Color(0xFFEF4444)
                                else -> Color(0xFFF59E0B)
                            }
                            
                            Box(
                                modifier = Modifier
                                    .background(bg, RoundedCornerShape(6.dp))
                                    .padding(horizontal = 8.dp, vertical = 4.dp)
                            ) {
                                Text(
                                    text = item.status,
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = textCol
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(8.dp))

                        Row(
                            horizontalArrangement = Arrangement.SpaceBetween,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = "PAN: ${item.pan}",
                                fontSize = 11.sp,
                                color = Color(0xFF64748B)
                            )
                            Text(
                                text = "FY ${item.financialYear} / AY ${item.assessmentYear}",
                                fontSize = 11.sp,
                                color = Color(0xFF64748B)
                            )
                        }
                    }
                }
            }
        }
    }
}
