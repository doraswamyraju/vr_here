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
import androidx.compose.foundation.lazy.rememberLazyListState
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.sbr.vrherebms.data.model.AddMessageRequest
import com.sbr.vrherebms.data.model.CreateTicketRequest
import com.sbr.vrherebms.data.model.TicketMessage
import com.sbr.vrherebms.data.model.TicketResponse
import com.sbr.vrherebms.data.remote.VRHereAPI
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminSupportScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val api = remember { VRHereAPI.getInstance(context) }

    var tickets by remember { mutableStateOf<List<TicketResponse>>(emptyList()) }
    var isLoading by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }
    var selectedCategory by remember { mutableStateOf("All") }
    var selectedStatus by remember { mutableStateOf("All") }
    var selectedTicket by remember { mutableStateOf<TicketResponse?>(null) }
    var showCreateDialog by remember { mutableStateOf(false) }

    val categories = listOf("All", "Service", "Billing", "Technical", "General")
    val statuses = listOf("All", "Open", "In Progress", "Resolved", "Closed")

    fun fetchTickets() {
        scope.launch {
            isLoading = true
            try {
                val res = api.getTickets()
                if (res.isSuccessful && res.body() != null) {
                    tickets = res.body()!!
                    selectedTicket?.let { current ->
                        val updated = tickets.find { it.id == current.id }
                        if (updated != null) selectedTicket = updated
                    }
                }
            } catch (e: Exception) {
                // Graceful fallback
            } finally {
                isLoading = false
            }
        }
    }

    LaunchedEffect(Unit) {
        fetchTickets()
    }

    val filteredTickets = remember(tickets, searchQuery, selectedCategory, selectedStatus) {
        tickets.filter { t ->
            val matchesCat = if (selectedCategory == "All") true else (t.category ?: "").equals(selectedCategory, ignoreCase = true)
            val matchesStatus = if (selectedStatus == "All") true else t.status.equals(selectedStatus, ignoreCase = true)
            val q = searchQuery.trim().lowercase()
            val matchesSearch = if (q.isBlank()) true else {
                t.subject.lowercase().contains(q) ||
                t.description.lowercase().contains(q) ||
                (t.ticketNumber ?: "").lowercase().contains(q) ||
                (t.user?.name ?: "").lowercase().contains(q)
            }
            matchesCat && matchesStatus && matchesSearch
        }
    }

    val openCount = remember(tickets) { tickets.count { it.status.equals("Open", ignoreCase = true) } }
    val inProgressCount = remember(tickets) { tickets.count { it.status.equals("In Progress", ignoreCase = true) } }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF8FAFC))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        if (selectedTicket != null) {
            // MODE 2: FULL TICKET CONVERSATION THREAD
            val currentTicket = selectedTicket!!
            var replyText by remember { mutableStateOf("") }
            var isSendingReply by remember { mutableStateOf(false) }
            val listState = rememberLazyListState()

            // Ticket Details Header
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Button(
                            onClick = { selectedTicket = null },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF1F5F9)),
                            shape = RoundedCornerShape(10.dp),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp)
                        ) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = Color(0xFF1E293B), modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Inbox", color = Color(0xFF1E293B), fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }

                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            // Status update chips
                            listOf("Open", "In Progress", "Resolved", "Closed").forEach { st ->
                                val isCur = currentTicket.status.equals(st, ignoreCase = true)
                                Box(
                                    modifier = Modifier
                                        .background(
                                            if (isCur) Color(0xFF4F46E5) else Color(0xFFF1F5F9),
                                            RoundedCornerShape(8.dp)
                                        )
                                        .clickable {
                                            scope.launch {
                                                try {
                                                    api.updateTicketStatus(currentTicket.id, mapOf("status" to st))
                                                } catch (_: Exception) {}
                                                selectedTicket = currentTicket.copy(status = st)
                                                fetchTickets()
                                                Toast.makeText(context, "Ticket marked $st", Toast.LENGTH_SHORT).show()
                                            }
                                        }
                                        .padding(horizontal = 8.dp, vertical = 5.dp)
                                ) {
                                    Text(
                                        text = st,
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = if (isCur) Color.White else Color(0xFF64748B)
                                    )
                                }
                            }
                        }
                    }

                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            currentTicket.ticketNumber?.let { tn ->
                                Text(text = "#$tn", color = Color(0xFF4F46E5), fontSize = 12.sp, fontWeight = FontWeight.Black)
                            }
                            Text(
                                text = currentTicket.subject,
                                fontSize = 15.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFF0F172A)
                            )
                        }
                        Text(
                            text = "Client: ${currentTicket.user?.name ?: "Valued Customer"} • Category: ${currentTicket.category ?: "General"} • Priority: ${currentTicket.priority}",
                            color = Color(0xFF64748B),
                            fontSize = 11.sp
                        )
                    }

                    if (currentTicket.description.isNotBlank()) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(Color(0xFFF8FAFC), RoundedCornerShape(10.dp))
                                .padding(10.dp)
                        ) {
                            Text(text = currentTicket.description, fontSize = 11.sp, color = Color(0xFF334155))
                        }
                    }
                }
            }

            // Message Timeline
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                contentPadding = PaddingValues(vertical = 8.dp)
            ) {
                if (currentTicket.messages.isEmpty()) {
                    item {
                        Box(
                            modifier = Modifier.fillMaxWidth().padding(top = 20.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text("No messages yet in this conversation.", color = Color(0xFF94A3B8), fontSize = 12.sp)
                        }
                    }
                } else {
                    items(currentTicket.messages) { msg ->
                        val isFromStaff = msg.sender?.role == "admin" || msg.sender?.role == "employee"
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = if (isFromStaff) Arrangement.End else Arrangement.Start
                        ) {
                            Card(
                                shape = RoundedCornerShape(16.dp),
                                colors = CardDefaults.cardColors(
                                    containerColor = if (isFromStaff) Color(0xFF4F46E5) else Color.White
                                ),
                                border = if (!isFromStaff) BorderStroke(1.dp, Color(0xFFE2E8F0)) else null,
                                modifier = Modifier.widthIn(max = 280.dp)
                            ) {
                                Column(modifier = Modifier.padding(12.dp)) {
                                    Text(
                                        text = msg.sender?.name ?: (if (isFromStaff) "VR HERE Support" else "Customer"),
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Black,
                                        color = if (isFromStaff) Color(0xFFE0E7FF) else Color(0xFF64748B)
                                    )
                                    Spacer(modifier = Modifier.height(3.dp))
                                    Text(
                                        text = msg.message,
                                        fontSize = 12.sp,
                                        color = if (isFromStaff) Color.White else Color(0xFF0F172A),
                                        lineHeight = 16.sp
                                    )
                                }
                            }
                        }
                    }
                }
            }

            // Reply input box
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 60.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedTextField(
                    value = replyText,
                    onValueChange = { replyText = it },
                    modifier = Modifier.weight(1f),
                    placeholder = { Text("Type reply to customer...", fontSize = 12.sp) },
                    shape = RoundedCornerShape(14.dp),
                    maxLines = 3
                )

                IconButton(
                    onClick = {
                        if (replyText.isBlank()) return@IconButton
                        isSendingReply = true
                        val textToSend = replyText
                        replyText = ""
                        scope.launch {
                            try {
                                val res = api.addTicketMessage(currentTicket.id, AddMessageRequest(textToSend))
                                if (res.isSuccessful && res.body() != null) {
                                    selectedTicket = res.body()!!
                                }
                                fetchTickets()
                            } catch (_: Exception) {}
                            isSendingReply = false
                        }
                    },
                    modifier = Modifier
                        .size(48.dp)
                        .background(Color(0xFF4F46E5), CircleShape)
                ) {
                    Icon(Icons.Default.Send, contentDescription = "Send", tint = Color.White, modifier = Modifier.size(20.dp))
                }
            }
        } else {
            // MODE 1: TICKETS INBOX OVERVIEW
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A))
            ) {
                Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        text = "CUSTOMER SERVICE & HELP DESK",
                        color = Color(0xFF38BDF8),
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Black,
                        letterSpacing = 1.sp
                    )
                    Text(
                        text = "Support Inbox",
                        color = Color.White,
                        fontSize = 22.sp,
                        fontWeight = FontWeight.Black
                    )
                    Text(
                        text = "Customer support inquiries, live resolution conversations, and SLA response management.",
                        color = Color(0xFF94A3B8),
                        fontSize = 11.sp,
                        lineHeight = 16.sp
                    )
                }
            }

            // Summary metrics
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
                        Text("Total Tickets", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B))
                        Spacer(modifier = Modifier.height(2.dp))
                        Text("${tickets.size}", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                    }
                }

                Card(
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text("Open Queue", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B))
                        Spacer(modifier = Modifier.height(2.dp))
                        Text("$openCount", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFFDC2626))
                    }
                }

                Card(
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text("In Progress", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B))
                        Spacer(modifier = Modifier.height(2.dp))
                        Text("$inProgressCount", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFF4F46E5))
                    }
                }
            }

            // Category filter chips
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                categories.forEach { cat ->
                    val isSel = selectedCategory == cat
                    Box(
                        modifier = Modifier
                            .background(if (isSel) Color(0xFF4F46E5) else Color.White, RoundedCornerShape(10.dp))
                            .border(1.dp, if (isSel) Color(0xFF4F46E5) else Color(0xFFE2E8F0), RoundedCornerShape(10.dp))
                            .clickable { selectedCategory = cat }
                            .padding(horizontal = 12.dp, vertical = 7.dp)
                    ) {
                        Text(
                            text = cat,
                            fontSize = 11.sp,
                            fontWeight = if (isSel) FontWeight.Black else FontWeight.Bold,
                            color = if (isSel) Color.White else Color(0xFF475569)
                        )
                    }
                }
            }

            // Search & Action
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(14.dp),
                    placeholder = { Text("Search tickets by subject, client...", fontSize = 12.sp) },
                    leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(16.dp)) },
                    singleLine = true
                )

                Button(
                    onClick = { showCreateDialog = true },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                    shape = RoundedCornerShape(14.dp),
                    contentPadding = PaddingValues(horizontal = 14.dp, vertical = 14.dp)
                ) {
                    Icon(Icons.Default.Add, contentDescription = "New Ticket", modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("New Ticket", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }
            }

            // Ticket cards list
            if (isLoading) {
                Box(modifier = Modifier.fillMaxWidth().weight(1f), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = Color(0xFF4F46E5))
                }
            } else if (filteredTickets.isEmpty()) {
                Box(modifier = Modifier.fillMaxWidth().weight(1f), contentAlignment = Alignment.Center) {
                    Text("No tickets found in Support Inbox.", color = Color(0xFF94A3B8), fontSize = 13.sp)
                }
            } else {
                LazyColumn(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                    contentPadding = PaddingValues(bottom = 90.dp)
                ) {
                    items(filteredTickets) { t ->
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { selectedTicket = t },
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                        ) {
                            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                                    ) {
                                        t.ticketNumber?.let { tn ->
                                            Text(text = "#$tn", color = Color(0xFF4F46E5), fontSize = 11.sp, fontWeight = FontWeight.Black)
                                        }
                                        Box(
                                            modifier = Modifier
                                                .background(
                                                    when (t.status.lowercase()) {
                                                        "open" -> Color(0xFFFEE2E2)
                                                        "resolved", "closed" -> Color(0xFFDCFCE7)
                                                        else -> Color(0xFFFEF3C7)
                                                    },
                                                    RoundedCornerShape(4.dp)
                                                )
                                                .padding(horizontal = 6.dp, vertical = 2.dp)
                                        ) {
                                            Text(
                                                text = t.status.uppercase(),
                                                fontSize = 9.sp,
                                                fontWeight = FontWeight.Black,
                                                color = when (t.status.lowercase()) {
                                                    "open" -> Color(0xFFDC2626)
                                                    "resolved", "closed" -> Color(0xFF16A34A)
                                                    else -> Color(0xFFD97706)
                                                }
                                            )
                                        }
                                    }

                                    Text(
                                        text = "${t.messages.size} msgs",
                                        fontSize = 11.sp,
                                        color = Color(0xFF64748B),
                                        fontWeight = FontWeight.Bold
                                    )
                                }

                                Text(
                                    text = t.subject,
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF0F172A),
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )

                                Text(
                                    text = t.description,
                                    fontSize = 11.sp,
                                    color = Color(0xFF64748B),
                                    maxLines = 2,
                                    overflow = TextOverflow.Ellipsis
                                )

                                Divider(color = Color(0xFFF8FAFC))

                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(
                                        text = "Client: ${t.user?.name ?: "Valued Customer"}",
                                        fontSize = 10.sp,
                                        color = Color(0xFF334155),
                                        fontWeight = FontWeight.SemiBold
                                    )
                                    Text(
                                        text = "Category: ${t.category ?: "General"}",
                                        fontSize = 10.sp,
                                        color = Color(0xFF64748B)
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Create New Ticket Dialog
    if (showCreateDialog) {
        var cat by remember { mutableStateOf("Service") }
        var subject by remember { mutableStateOf("") }
        var desc by remember { mutableStateOf("") }
        var prio by remember { mutableStateOf("Medium") }

        Dialog(onDismissRequest = { showCreateDialog = false }) {
            Card(
                modifier = Modifier.fillMaxWidth().padding(8.dp),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp).verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text("Create Support Ticket", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))

                    OutlinedTextField(
                        value = subject,
                        onValueChange = { subject = it },
                        label = { Text("Ticket Subject") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp)
                    )

                    OutlinedTextField(
                        value = desc,
                        onValueChange = { desc = it },
                        label = { Text("Issue Details / Description") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp),
                        minLines = 3
                    )

                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                        TextButton(onClick = { showCreateDialog = false }) {
                            Text("Cancel", color = Color(0xFF64748B))
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Button(
                            onClick = {
                                if (subject.isBlank()) {
                                    Toast.makeText(context, "Please enter ticket subject", Toast.LENGTH_SHORT).show()
                                    return@Button
                                }
                                scope.launch {
                                    try {
                                        api.createTicket(
                                            CreateTicketRequest(
                                                category = cat,
                                                subject = subject,
                                                description = desc,
                                                priority = prio
                                            )
                                        )
                                    } catch (_: Exception) {}
                                    fetchTickets()
                                    showCreateDialog = false
                                    Toast.makeText(context, "Ticket created successfully", Toast.LENGTH_SHORT).show()
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Text("Create Ticket", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }
    }
}
