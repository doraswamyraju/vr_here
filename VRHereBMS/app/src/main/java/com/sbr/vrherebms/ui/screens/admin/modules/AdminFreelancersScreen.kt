package com.sbr.vrherebms.ui.screens.admin.modules

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
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

data class MockFreelancer(
    val id: String,
    val name: String,
    val email: String,
    val domain: String,
    val status: String
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminFreelancersScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    var searchQuery by remember { mutableStateOf("") }

    val freelancers = remember {
        listOf(
            MockFreelancer("1", "Rajesh Kumar", "rajesh.ca@gmail.com", "Accounting", "Active"),
            MockFreelancer("2", "Lakshmi Prasad", "lakshmi.cs@outlook.com", "Legal Compliance", "Pending Approval"),
            MockFreelancer("3", "Sai Teja", "saiteja.tax@gmail.com", "GST Filing", "Active"),
            MockFreelancer("4", "Priya Vardhan", "priya.v@gmail.com", "ITR Reviewer", "Suspended")
        )
    }

    val filtered = remember(searchQuery) {
        freelancers.filter {
            it.name.contains(searchQuery, ignoreCase = true) ||
                    it.domain.contains(searchQuery, ignoreCase = true)
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
            placeholder = { Text("Search freelancers...", fontSize = 14.sp) },
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
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column {
                            Text(
                                text = item.name,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF1E293B)
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = "Domain: ${item.domain} • ${item.email}",
                                fontSize = 11.sp,
                                color = Color(0xFF64748B)
                            )
                        }

                        val bg = when(item.status) {
                            "Active" -> Color(0xFFECFDF5)
                            "Suspended" -> Color(0xFFFEF2F2)
                            else -> Color(0xFFFFF7ED)
                        }
                        val textCol = when(item.status) {
                            "Active" -> Color(0xFF10B981)
                            "Suspended" -> Color(0xFFEF4444)
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
                }
            }
        }
    }
}
