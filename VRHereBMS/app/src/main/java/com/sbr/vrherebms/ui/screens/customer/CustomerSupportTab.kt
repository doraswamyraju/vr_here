package com.sbr.vrherebms.ui.screens.customer

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.SupportAgent
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel

@Composable
fun CustomerSupportTab(viewModel: CustomerDashboardViewModel) {
    var isNewTicketOpen by remember { mutableStateOf(false) }

    if (isNewTicketOpen) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(20.dp)
                .verticalScroll(rememberScrollState())
                .padding(bottom = 120.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .scaleOnPress()
                    .clickable { isNewTicketOpen = false }
            ) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = Color(0xFF6366F1))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Back to Tickets", color = Color(0xFF6366F1), fontWeight = FontWeight.Bold, fontSize = 13.sp)
            }

            Text("Raise Support Ticket", fontSize = 20.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))

            OutlinedTextField(
                value = viewModel.ticketSubject,
                onValueChange = { viewModel.ticketSubject = it },
                label = { Text("Subject") },
                singleLine = true,
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            )

            OutlinedTextField(
                value = viewModel.ticketDescription,
                onValueChange = { viewModel.ticketDescription = it },
                label = { Text("Query Description") },
                minLines = 4,
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth()
            )

            Button(
                onClick = {
                    viewModel.createSupportTicket()
                    isNewTicketOpen = false
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp)
                    .scaleOnPress(),
                shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6366F1))
            ) {
                Text("Submit Ticket", fontWeight = FontWeight.Bold)
            }
        }
    } else {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            contentPadding = PaddingValues(top = 16.dp, bottom = 120.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text("Help & Support", fontSize = 22.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                        Text("Raise tickets directly with CA/CS professionals.", fontSize = 12.sp, color = Color(0xFF64748B), modifier = Modifier.padding(top = 2.dp))
                    }
                    Button(
                        onClick = { isNewTicketOpen = true },
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6366F1)),
                        modifier = Modifier.scaleOnPress(),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                    ) {
                        Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Raise", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }

            if (viewModel.tickets.isEmpty()) {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(24.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(48.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Icon(Icons.Default.SupportAgent, contentDescription = null, tint = Color(0xFFCBD5E1), modifier = Modifier.size(48.dp))
                                Spacer(modifier = Modifier.height(12.dp))
                                Text("No support tickets raised yet", color = Color(0xFF64748B), fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            } else {
                items(viewModel.tickets) { ticket ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(24.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFF1F5F9))
                    ) {
                        Column(modifier = Modifier.padding(20.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(ticket.subject, fontWeight = FontWeight.Black, fontSize = 14.sp, color = Color(0xFF1E293B))
                                Box(
                                    modifier = Modifier
                                        .background(
                                            color = when (ticket.status) {
                                                "Closed" -> Color(0xFFEEF2F6)
                                                else -> Color(0xFFFEF3C7)
                                            },
                                            shape = RoundedCornerShape(6.dp)
                                        )
                                        .padding(horizontal = 8.dp, vertical = 4.dp)
                                ) {
                                    Text(
                                        text = ticket.status,
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Black,
                                        color = if (ticket.status == "Closed") Color(0xFF64748B) else Color(0xFF92400E)
                                    )
                                }
                            }
                            Text(
                                ticket.description,
                                fontSize = 12.sp,
                                color = Color(0xFF64748B),
                                modifier = Modifier.padding(top = 10.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}
