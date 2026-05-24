package com.sbr.vrherebms.ui.screens.admin.modules

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
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

data class SupportTicket(
    val id: String,
    val clientName: String,
    val subject: String,
    val message: String,
    val priority: String, // 'High', 'Medium', 'Low'
    var status: String, // 'Open', 'Resolved'
    val chatMessages: List<Pair<String, String>> // Sender, Msg text
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminSupportScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var activeFilter by remember { mutableStateOf("All") }
    var selectedTicket by remember { mutableStateOf<SupportTicket?>(null) }

    var ticketsList by remember {
        mutableStateOf(
            listOf(
                SupportTicket(
                    "1",
                    "Rajugari Ventures",
                    "Incorrect PAN number in SPICe+ draft",
                    "Hi Admin, the PAN card number specified in my Spice draft Part-B is wrong. The correct number is ABCDE1234F. Please modify it.",
                    "High",
                    "Open",
                    listOf(
                        "Client" to "Hi Admin, the PAN card number specified in my Spice draft Part-B is wrong. The correct number is ABCDE1234F. Please modify it."
                    )
                ),
                SupportTicket(
                    "2",
                    "Blue Cat Solutions",
                    "GST login credentials not received",
                    "Hi VR Here team, I successfully completed my GST registration paid order 4 days ago but haven't received my portal GSTIN logins yet. Let me know.",
                    "Medium",
                    "Open",
                    listOf(
                        "Client" to "Hi VR Here team, I successfully completed my GST registration paid order 4 days ago but haven't received my portal GSTIN logins yet. Let me know."
                    )
                ),
                SupportTicket(
                    "3",
                    "Gayatri Enterprises",
                    "Invoice download link broken",
                    "Hi, when I click on invoice download under my finance ledger tab, it fails with a 404 file not found error. Please mail my receipt.",
                    "Low",
                    "Resolved",
                    listOf(
                        "Client" to "Hi, when I click on invoice download under my finance ledger tab, it fails with a 404 file not found error. Please mail my receipt.",
                        "Admin" to "Hi Gayatri, we have updated the invoice PDF download link and also mailed the copy to your email address. Feel free to review it!"
                    )
                )
            )
        )
    }

    val filteredTickets = remember(activeFilter, ticketsList) {
        ticketsList.filter {
            activeFilter == "All" || it.status.equals(activeFilter, ignoreCase = true)
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF1F5F9))
    ) {
        // 1. Sleek purple command header
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1B4B))
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Text(
                    text = "CLIENT SUPPORT HUB",
                    color = Color(0xFF38BDF8),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.ExtraBold,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Client Support Desk",
                    color = Color.White,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Review customer support tickets, answer PAN/GST related inquiries, and manage resolution states.",
                    color = Color(0xFF94A3B8),
                    fontSize = 12.sp,
                    lineHeight = 16.sp
                )
            }
        }

        // 2. Tab Filter
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            listOf("All", "Open", "Resolved").forEach { status ->
                val isSelected = activeFilter == status
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
                        .clickable { activeFilter = status }
                        .padding(horizontal = 16.dp, vertical = 8.dp)
                ) {
                    Text(
                        text = status.uppercase(),
                        color = if (isSelected) Color.White else Color(0xFF64748B),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Black
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 3. Ticket cards list
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            items(filteredTickets) { ticket ->
                val priorityColor = when (ticket.priority) {
                    "High" -> Color(0xFFEF4444)
                    "Medium" -> Color(0xFFF59E0B)
                    else -> Color(0xFF94A3B8)
                }

                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { selectedTicket = ticket },
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
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(8.dp)
                                        .background(priorityColor, CircleShape)
                                )
                                Text(
                                    text = ticket.priority.uppercase() + " PRIORITY",
                                    color = priorityColor,
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Black
                                )
                            }

                            Box(
                                modifier = Modifier
                                    .background(
                                        if (ticket.status == "Open") Color(0xFFFFECEC) else Color(0xFFECFDF5),
                                        RoundedCornerShape(6.dp)
                                    )
                                    .padding(horizontal = 8.dp, vertical = 2.dp)
                            ) {
                                Text(
                                    text = ticket.status.uppercase(),
                                    color = if (ticket.status == "Open") Color(0xFFEF4444) else Color(0xFF10B981),
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Black
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(10.dp))
                        Text(
                            text = ticket.subject,
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF1E293B)
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = ticket.message,
                            fontSize = 11.sp,
                            color = Color(0xFF64748B),
                            lineHeight = 16.sp
                        )

                        Spacer(modifier = Modifier.height(12.dp))
                        Divider(color = Color(0xFFF1F5F9))
                        Spacer(modifier = Modifier.height(10.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "Client: ${ticket.clientName}",
                                fontSize = 11.sp,
                                color = Color(0xFF475569),
                                fontWeight = FontWeight.Bold
                            )

                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Icon(Icons.Default.Chat, contentDescription = null, tint = Color(0xFF4F46E5), modifier = Modifier.size(12.dp))
                                Text(
                                    text = "Reply thread",
                                    color = Color(0xFF4F46E5),
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                        }
                    }
                }
            }

            if (filteredTickets.isEmpty()) {
                item {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 40.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "No support tickets match filters.",
                            color = Color(0xFF64748B),
                            fontSize = 12.sp,
                            textAlign = TextAlign.Center
                        )
                    }
                }
            }
        }
    }

    // Support chat thread modal Dialog
    selectedTicket?.let { ticket ->
        var replyText by remember { mutableStateOf("") }

        Dialog(onDismissRequest = { selectedTicket = null }) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(480.dp)
                    .padding(8.dp),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFF1F5F9))
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(20.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(
                                text = ticket.clientName,
                                fontSize = 15.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF1E293B)
                            )
                            Text(
                                text = ticket.subject,
                                fontSize = 11.sp,
                                color = Color(0xFF64748B),
                                maxLines = 1
                            )
                        }

                        IconButton(onClick = { selectedTicket = null }) {
                            Icon(Icons.Default.Close, contentDescription = null, tint = Color(0xFF64748B))
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))
                    Divider(color = Color(0xFFF1F5F9))

                    // Chat message thread column
                    LazyColumn(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxWidth()
                            .padding(vertical = 12.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(ticket.chatMessages) { (sender, text) ->
                            val isAdmin = sender == "Admin"
                            val bubbleColor = if (isAdmin) Color(0xFFE0E7FF) else Color(0xFFF1F5F9)
                            val align = if (isAdmin) Alignment.End else Alignment.Start

                            Column(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalAlignment = align
                            ) {
                                Box(
                                    modifier = Modifier
                                        .background(
                                            bubbleColor,
                                            RoundedCornerShape(
                                                topStart = 12.dp,
                                                topEnd = 12.dp,
                                                bottomStart = if (isAdmin) 12.dp else 0.dp,
                                                bottomEnd = if (isAdmin) 0.dp else 12.dp
                                            )
                                        )
                                        .padding(12.dp)
                                ) {
                                    Text(
                                        text = text,
                                        fontSize = 11.sp,
                                        color = Color(0xFF1E293B),
                                        lineHeight = 16.sp
                                    )
                                }
                                Text(
                                    text = sender,
                                    fontSize = 8.sp,
                                    color = Color(0xFF94A3B8),
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp)
                                )
                            }
                        }
                    }

                    Divider(color = Color(0xFFF1F5F9))
                    Spacer(modifier = Modifier.height(10.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        OutlinedTextField(
                            value = replyText,
                            onValueChange = { replyText = it },
                            placeholder = { Text("Write response reply...", fontSize = 12.sp) },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(12.dp),
                            singleLine = true
                        )

                        Button(
                            onClick = {
                                if (replyText.isBlank()) return@Button
                                val updatedMessages = ticket.chatMessages + ("Admin" to replyText)
                                ticketsList = ticketsList.map { old ->
                                    if (old.id == ticket.id) old.copy(chatMessages = updatedMessages) else old
                                }
                                Toast.makeText(context, "Reply dispatched!", Toast.LENGTH_SHORT).show()
                                replyText = ""
                                selectedTicket = null
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.height(48.dp)
                        ) {
                            Icon(Icons.Default.Send, contentDescription = null, modifier = Modifier.size(16.dp))
                        }
                    }
                }
            }
        }
    }
}
