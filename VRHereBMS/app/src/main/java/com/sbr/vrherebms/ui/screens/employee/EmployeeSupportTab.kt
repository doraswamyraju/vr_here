package com.sbr.vrherebms.ui.screens.employee

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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.EmployeeDashboardViewModel
import com.sbr.vrherebms.data.model.TicketResponse

@Composable
fun EmployeeSupportTab(viewModel: EmployeeDashboardViewModel) {
    val tickets = viewModel.supportTickets
    var searchQuery by remember { mutableStateOf("") }
    
    val filteredTickets = remember(tickets, searchQuery) {
        if (searchQuery.isBlank()) tickets
        else tickets.filter {
            it.subject.contains(searchQuery, ignoreCase = true) ||
            it.description.contains(searchQuery, ignoreCase = true)
        }
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "Customer Support",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF1E293B)
                )
                Text(
                    text = "Track assigned query tickets and client requests.",
                    fontSize = 12.sp,
                    color = Color(0xFF64748B)
                )
            }
        }

        // Search Bar Widget
        item {
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = { Text("Search tickets...") },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = Color(0xFF94A3B8)) },
                shape = RoundedCornerShape(16.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = Color(0xFF6366F1),
                    unfocusedBorderColor = Color(0xFFE2E8F0)
                ),
                modifier = Modifier.fillMaxWidth()
            )
        }

        if (filteredTickets.isEmpty()) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 48.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(
                            Icons.Default.QuestionAnswer,
                            contentDescription = null,
                            tint = Color(0xFFCBD5E1),
                            modifier = Modifier.size(48.dp)
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "No tickets found.",
                            color = Color(0xFF64748B),
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        } else {
            items(filteredTickets) { ticket ->
                SupportTicketCard(ticket = ticket)
            }
        }

        item {
            Spacer(modifier = Modifier.height(60.dp))
        }
    }
}

@Composable
fun SupportTicketCard(ticket: TicketResponse) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.Top
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = ticket.subject,
                        fontWeight = FontWeight.Black,
                        fontSize = 14.sp,
                        color = Color(0xFF1E293B)
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = ticket.description,
                        fontSize = 11.sp,
                        color = Color(0xFF64748B),
                        maxLines = 2
                    )
                }
                
                Spacer(modifier = Modifier.width(8.dp))
                
                Box(
                    modifier = Modifier
                        .background(
                            color = when (ticket.status) {
                                "Closed" -> Color(0xFFE2E8F0)
                                "In Progress" -> Color(0xFFFEF3C7)
                                else -> Color(0xFFD1FAE5)
                            },
                            shape = RoundedCornerShape(8.dp)
                        )
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = ticket.status,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Black,
                        color = when (ticket.status) {
                            "Closed" -> Color(0xFF475569)
                            "In Progress" -> Color(0xFF92400E)
                            else -> Color(0xFF065F46)
                        }
                    )
                }
            }

            Divider(modifier = Modifier.padding(vertical = 12.dp), color = Color(0xFFF1F5F9))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .background(
                                color = when (ticket.priority) {
                                    "High" -> Color(0xFFFEE2E2)
                                    "Medium" -> Color(0xFFFEF3C7)
                                    else -> Color(0xFFE0E7FF)
                                },
                                shape = RoundedCornerShape(6.dp)
                            )
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = "${ticket.priority} Priority",
                            fontSize = 8.sp,
                            fontWeight = FontWeight.Black,
                            color = when (ticket.priority) {
                                "High" -> Color(0xFF991B1B)
                                "Medium" -> Color(0xFF92400E)
                                else -> Color(0xFF3730A3)
                            }
                        )
                    }
                }
                Text(
                    text = if (ticket.createdAt.isNotEmpty()) formatLogTime(ticket.createdAt) else "Just now",
                    fontSize = 10.sp,
                    color = Color(0xFF94A3B8),
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}
