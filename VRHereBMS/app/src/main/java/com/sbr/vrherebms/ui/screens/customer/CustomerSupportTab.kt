package com.sbr.vrherebms.ui.screens.customer

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.AddMessageRequest
import com.sbr.vrherebms.data.model.CreateTicketRequest
import com.sbr.vrherebms.data.model.TicketResponse
import com.sbr.vrherebms.data.remote.VRHereAPI
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomerSupportTab(
    viewModel: CustomerDashboardViewModel,
    onChatStateChanged: (Boolean) -> Unit = {},
    autoOpenRaiseTicket: Int = 0
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val api = remember { VRHereAPI.getInstance(context) }

    val ticketsList = viewModel.tickets
    val ordersList = viewModel.orders

    // Screen State
    var selectedFilter by remember { mutableStateOf("all") } // "all" | "open" | "progress" | "closed"
    var selectedTicket by remember { mutableStateOf<TicketResponse?>(null) }

    // Notify parent whenever chat state changes
    LaunchedEffect(selectedTicket) {
        onChatStateChanged(selectedTicket != null)
    }

    // Raise Ticket Bottom Sheet State
    var showRaiseTicketSheet by remember { mutableStateOf(false) }

    LaunchedEffect(autoOpenRaiseTicket) {
        if (autoOpenRaiseTicket > 0) {
            showRaiseTicketSheet = true
        }
    }
    var selectedCategoryForTicket by remember { mutableStateOf("Service") } // "Workflow" | "Technical" | "Service" | "Support"
    var ticketSubjectInput by remember { mutableStateOf("") }
    var ticketDescriptionInput by remember { mutableStateOf("") }
    var ticketPriorityInput by remember { mutableStateOf("Medium") } // "Low" | "Medium" | "High" | "Urgent"
    var isSubmittingTicket by remember { mutableStateOf(false) }

    // Reply Message Input inside Ticket Conversation
    var replyText by remember { mutableStateOf("") }
    var isSendingReply by remember { mutableStateOf(false) }

    val filteredTickets = remember(ticketsList, selectedFilter) {
        ticketsList.filter { ticket ->
            val st = ticket.status.lowercase()
            when (selectedFilter) {
                "open" -> st == "open"
                "progress" -> st == "in progress" || st == "progress" || st == "resolved"
                "closed" -> st == "closed"
                else -> true
            }
        }
    }

    if (selectedTicket != null) {
        // ==================== TICKET CONVERSATION CHAT VIEW ====================
        val ticket = selectedTicket!!
        val isClosed = ticket.status == "Closed"

        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(Color(0xFFF8FAFC))
        ) {
            // Chat Header Bar
            Surface(
                color = Color.White,
                border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconButton(
                        onClick = { selectedTicket = null },
                        modifier = Modifier
                            .size(36.dp)
                            .background(Color(0xFFF1F5F9), CircleShape)
                    ) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = Color(0xFF0F172A), modifier = Modifier.size(18.dp))
                    }
                    Spacer(modifier = Modifier.width(10.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = ticket.subject,
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Black,
                            color = Color(0xFF0F172A),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = "Ticket #${ticket.id.takeLast(6).uppercase()} • Priority: ${ticket.priority}",
                            fontSize = 11.sp,
                            color = Color(0xFF64748B)
                        )
                    }

                    Surface(
                        shape = RoundedCornerShape(6.dp),
                        color = when (ticket.status) {
                            "Closed" -> Color(0xFFF1F5F9)
                            "In Progress" -> Color(0xFFDBEAFE)
                            else -> Color(0xFFFEF3C7)
                        }
                    ) {
                        Text(
                            text = ticket.status.uppercase(),
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Black,
                            color = when (ticket.status) {
                                "Closed" -> Color(0xFF64748B)
                                "In Progress" -> Color(0xFF1D4ED8)
                                else -> Color(0xFFB45309)
                            },
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                        )
                    }
                }
            }

            // Message Thread Messages List
            LazyColumn(
                modifier = Modifier
                    .weight(1f)
                    .padding(horizontal = 16.dp),
                contentPadding = PaddingValues(vertical = 16.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                // Initial Query Description Message Card
                item {
                    Surface(
                        shape = RoundedCornerShape(16.dp),
                        color = Color.White,
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                    Surface(shape = CircleShape, color = Color(0xFFFEF2F2), modifier = Modifier.size(24.dp)) {
                                        Box(contentAlignment = Alignment.Center) {
                                            Icon(Icons.Default.Person, contentDescription = null, tint = Color(0xFFDC2626), modifier = Modifier.size(14.dp))
                                        }
                                    }
                                    Text("You (Client)", fontSize = 11.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                }
                                Text(if (ticket.createdAt.length >= 10) ticket.createdAt.substring(0, 10) else "Initial Query", fontSize = 10.sp, color = Color(0xFF94A3B8))
                            }
                            Text(ticket.description, fontSize = 12.sp, color = Color(0xFF334155), lineHeight = 16.sp)
                        }
                    }
                }

                // Replies List
                items(ticket.messages) { msg ->
                    val isClientMessage = msg.sender?.role == "client" || msg.sender == null
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = if (isClientMessage) Arrangement.End else Arrangement.Start
                    ) {
                        Surface(
                            shape = RoundedCornerShape(16.dp),
                            color = if (isClientMessage) Color(0xFFDC2626) else Color.White,
                            border = BorderStroke(1.dp, if (isClientMessage) Color(0xFFDC2626) else Color(0xFFE2E8F0)),
                            modifier = Modifier.widthIn(max = 280.dp)
                        ) {
                            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(
                                    text = if (isClientMessage) "You" else (msg.sender?.name ?: "Compliance Lead / CA"),
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Black,
                                    color = if (isClientMessage) Color(0xFFFECDD3) else Color(0xFF2563EB)
                                )
                                Text(
                                    text = msg.message,
                                    fontSize = 12.sp,
                                    color = if (isClientMessage) Color.White else Color(0xFF0F172A),
                                    lineHeight = 16.sp
                                )
                            }
                        }
                    }
                }
            }

            // Reply Input Bar (if not closed)
            if (!isClosed) {
                Surface(
                    color = Color.White,
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = replyText,
                            onValueChange = { replyText = it },
                            placeholder = { Text("Type reply for CA advisor...") },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(20.dp),
                            singleLine = true
                        )

                        Button(
                            onClick = {
                                if (replyText.isBlank()) return@Button
                                isSendingReply = true
                                scope.launch {
                                    try {
                                        val res = api.addTicketMessage(ticket.id, AddMessageRequest(replyText))
                                        if (res.isSuccessful && res.body() != null) {
                                            selectedTicket = res.body()
                                            viewModel.refreshAllData(silent = true)
                                            replyText = ""
                                        } else {
                                            Toast.makeText(context, "Failed to send reply", Toast.LENGTH_SHORT).show()
                                        }
                                    } catch (e: Exception) {
                                        Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
                                    } finally {
                                        isSendingReply = false
                                    }
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                            shape = CircleShape,
                            modifier = Modifier.size(44.dp),
                            contentPadding = PaddingValues(0.dp)
                        ) {
                            if (isSendingReply) {
                                CircularProgressIndicator(color = Color.White, modifier = Modifier.size(18.dp))
                            } else {
                                Icon(Icons.Default.Send, contentDescription = "Send", tint = Color.White, modifier = Modifier.size(18.dp))
                            }
                        }
                    }
                }
            }
        }
    } else {
        // ==================== MAIN TICKET CENTER LIST VIEW ====================
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .background(Color(0xFFF8FAFC)),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // --- 1. HERO BANNER & HELPLINES ---
            item {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Card(
                        shape = RoundedCornerShape(24.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.Transparent),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(
                                    brush = Brush.horizontalGradient(
                                        listOf(Color(0xFF881337), Color(0xFFBE123C), Color(0xFFE11D48))
                                    ),
                                    shape = RoundedCornerShape(24.dp)
                                )
                                .padding(20.dp)
                        ) {
                            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Surface(
                                    color = Color.White.copy(alpha = 0.2f),
                                    shape = RoundedCornerShape(50)
                                ) {
                                    Text(
                                        "CA & LEGAL ADVISORY DESK",
                                        color = Color.White,
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Black,
                                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                                    )
                                }
                                Text("Help & Support Tickets", color = Color.White, fontSize = 22.sp, fontWeight = FontWeight.Black)
                                Text("Raise tickets directly with CA/CS experts and compliance leads for priority assistance.", color = Color(0xFFFFE4E6), fontSize = 12.sp)

                                Spacer(modifier = Modifier.height(4.dp))
                                Button(
                                    onClick = { showRaiseTicketSheet = true },
                                    colors = ButtonDefaults.buttonColors(containerColor = Color.White),
                                    shape = RoundedCornerShape(12.dp)
                                ) {
                                    Icon(Icons.Default.Add, contentDescription = null, tint = Color(0xFFBE123C), modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Raise New Support Ticket", fontSize = 11.sp, fontWeight = FontWeight.Black, color = Color(0xFFBE123C))
                                }
                            }
                        }
                    }

                    // Direct Helpline Action Cards Row
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        // WhatsApp Helpline Card
                        Card(
                            modifier = Modifier
                                .weight(1f)
                                .clickable {
                                    try {
                                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://wa.me/918008530606"))
                                        context.startActivity(intent)
                                    } catch (e: Exception) {}
                                },
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFFECFDF5)),
                            border = BorderStroke(1.dp, Color(0xFFA7F3D0))
                        ) {
                            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                    Icon(Icons.Default.Chat, contentDescription = null, tint = Color(0xFF047857), modifier = Modifier.size(16.dp))
                                    Text("WhatsApp", fontSize = 12.sp, fontWeight = FontWeight.Black, color = Color(0xFF064E3B))
                                }
                                Text("Instant CA Support", fontSize = 10.sp, color = Color(0xFF047857))
                            }
                        }

                        // Call Direct Helpline Card
                        Card(
                            modifier = Modifier
                                .weight(1f)
                                .clickable {
                                    try {
                                        val intent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:918008530606"))
                                        context.startActivity(intent)
                                    } catch (e: Exception) {}
                                },
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFFEFF6FF)),
                            border = BorderStroke(1.dp, Color(0xFFBFDBFE))
                        ) {
                            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                    Icon(Icons.Default.Phone, contentDescription = null, tint = Color(0xFF1D4ED8), modifier = Modifier.size(16.dp))
                                    Text("Call Helpline", fontSize = 12.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E40AF))
                                }
                                Text("+91 80085 30606", fontSize = 10.sp, color = Color(0xFF2563EB))
                            }
                        }
                    }
                }
            }

            // --- 2. TICKET CATEGORY FILTER CHIPS ---
            item {
                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    val filters = listOf(
                        "all" to "All (${ticketsList.size})",
                        "open" to "Open (${ticketsList.count { it.status == "Open" }})",
                        "progress" to "In Progress (${ticketsList.count { it.status == "In Progress" }})",
                        "closed" to "Closed (${ticketsList.count { it.status == "Closed" }})"
                    )
                    items(filters) { (key, label) ->
                        val isSelected = selectedFilter == key
                        Surface(
                            shape = RoundedCornerShape(12.dp),
                            color = if (isSelected) Color(0xFFDC2626) else Color.White,
                            border = BorderStroke(1.dp, if (isSelected) Color(0xFFDC2626) else Color(0xFFE2E8F0)),
                            modifier = Modifier.clickable { selectedFilter = key }
                        ) {
                            Text(
                                text = label,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                color = if (isSelected) Color.White else Color(0xFF475569),
                                modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp)
                            )
                        }
                    }
                }
            }

            // --- 3. TICKETS LIST ---
            if (filteredTickets.isEmpty()) {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(
                            modifier = Modifier.padding(32.dp).fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Icon(Icons.Default.SupportAgent, contentDescription = null, tint = Color.LightGray, modifier = Modifier.size(44.dp))
                            Text("No support tickets in this view", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF64748B))
                            Button(
                                onClick = { showRaiseTicketSheet = true },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                                shape = RoundedCornerShape(10.dp)
                            ) {
                                Text("Raise New Support Ticket", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            } else {
                items(filteredTickets) { ticket ->
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { selectedTicket = ticket },
                        shape = RoundedCornerShape(18.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                    ) {
                        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Surface(shape = RoundedCornerShape(6.dp), color = Color(0xFFF1F5F9)) {
                                        Text("#TCK-${ticket.id.takeLast(6).uppercase()}", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF475569), modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                                    }
                                    Surface(shape = RoundedCornerShape(6.dp), color = Color(0xFFFEF2F2)) {
                                        Text(ticket.priority.uppercase(), fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFFBE123C), modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                                    }
                                }

                                Surface(
                                    shape = RoundedCornerShape(6.dp),
                                    color = when (ticket.status) {
                                        "Closed" -> Color(0xFFF1F5F9)
                                        "In Progress" -> Color(0xFFDBEAFE)
                                        else -> Color(0xFFFEF3C7)
                                    }
                                ) {
                                    Text(
                                        text = ticket.status.uppercase(),
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Black,
                                        color = when (ticket.status) {
                                            "Closed" -> Color(0xFF64748B)
                                            "In Progress" -> Color(0xFF1D4ED8)
                                            else -> Color(0xFFB45309)
                                        },
                                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                                    )
                                }
                            }

                            Text(
                                text = ticket.subject,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFF0F172A),
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )

                            Text(
                                text = ticket.description,
                                fontSize = 12.sp,
                                color = Color(0xFF64748B),
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis
                            )

                            HorizontalDivider(color = Color(0xFFF1F5F9))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = "${ticket.messages.size} Messages • Tapped to Open Discussion",
                                    fontSize = 11.sp,
                                    color = Color(0xFF94A3B8)
                                )
                                Text(
                                    text = "View Chat ›",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFFDC2626)
                                )
                            }
                        }
                    }
                }
            }

            item {
                Spacer(modifier = Modifier.height(80.dp))
            }
        }
    }

    // --- RAISE NEW SUPPORT TICKET MODAL BOTTOM SHEET (MATCHING WEB 100%) ---
    if (showRaiseTicketSheet) {
        ModalBottomSheet(
            onDismissRequest = { showRaiseTicketSheet = false },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            containerColor = Color.White
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Modal Header
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Surface(
                            shape = RoundedCornerShape(50),
                            color = Color(0xFFFEF2F2),
                            border = BorderStroke(1.dp, Color(0xFFFECDD3))
                        ) {
                            Text(
                                "NEW SUPPORT REQUEST",
                                color = Color(0xFFDC2626),
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Black,
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 3.dp)
                            )
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        Text("Raise Support Ticket", fontSize = 18.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                    }
                    IconButton(
                        onClick = { showRaiseTicketSheet = false },
                        modifier = Modifier
                            .size(32.dp)
                            .background(Color(0xFFF1F5F9), CircleShape)
                    ) {
                        Icon(Icons.Default.Close, contentDescription = "Close", tint = Color(0xFF64748B), modifier = Modifier.size(16.dp))
                    }
                }

                // 1. SELECT DEPARTMENT / CATEGORY GRID (4 Cards matching Web)
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("SELECT DEPARTMENT / CATEGORY", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B), letterSpacing = 0.5.sp)
                    
                    val categories = listOf(
                        CategoryConfig("Workflow", "Workflow Issue", "Internal blocker, quality audit flag, or client document gap", Icons.Default.Security),
                        CategoryConfig("Technical", "Technical", "Website issues, login, file uploads, or gateway errors", Icons.Default.Build),
                        CategoryConfig("Service", "Service", "Filing status, MCA queries, CA review, and incorporation", Icons.Default.BusinessCenter),
                        CategoryConfig("Support", "Support", "Billing, tax invoices, receipts, and general inquiries", Icons.Default.SupportAgent)
                    )

                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        categories.chunked(2).forEach { rowCategories ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                rowCategories.forEach { cat ->
                                    val isSelected = selectedCategoryForTicket == cat.key
                                    Card(
                                        modifier = Modifier
                                            .weight(1f)
                                            .clickable { selectedCategoryForTicket = cat.key },
                                        shape = RoundedCornerShape(14.dp),
                                        colors = CardDefaults.cardColors(
                                            containerColor = if (isSelected) Color(0xFF0F172A) else Color(0xFFF8FAFC)
                                        ),
                                        border = BorderStroke(
                                            1.dp,
                                            if (isSelected) Color(0xFF0F172A) else Color(0xFFE2E8F0)
                                        )
                                    ) {
                                        Column(
                                            modifier = Modifier.padding(10.dp),
                                            verticalArrangement = Arrangement.spacedBy(4.dp)
                                        ) {
                                            Row(
                                                verticalAlignment = Alignment.CenterVertically,
                                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                                            ) {
                                                Icon(
                                                    cat.icon,
                                                    contentDescription = null,
                                                    tint = if (isSelected) Color(0xFFF43F5E) else Color(0xFF0F172A),
                                                    modifier = Modifier.size(16.dp)
                                                )
                                                Text(
                                                    cat.title,
                                                    fontSize = 11.sp,
                                                    fontWeight = FontWeight.Black,
                                                    color = if (isSelected) Color.White else Color(0xFF0F172A)
                                                )
                                            }
                                            Text(
                                                cat.desc,
                                                fontSize = 9.sp,
                                                color = if (isSelected) Color(0xFF94A3B8) else Color(0xFF64748B),
                                                lineHeight = 12.sp,
                                                maxLines = 2,
                                                overflow = TextOverflow.Ellipsis
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // 2. URGENCY LEVEL PILLS
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("URGENCY LEVEL", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B), letterSpacing = 0.5.sp)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        listOf("Low", "Medium", "High", "Urgent").forEach { p ->
                            val isSel = ticketPriorityInput == p
                            Surface(
                                shape = RoundedCornerShape(10.dp),
                                color = if (isSel) Color(0xFF0F172A) else Color(0xFFF8FAFC),
                                border = BorderStroke(1.dp, if (isSel) Color(0xFF0F172A) else Color(0xFFE2E8F0)),
                                modifier = Modifier
                                    .weight(1f)
                                    .clickable { ticketPriorityInput = p }
                            ) {
                                Box(
                                    contentAlignment = Alignment.Center,
                                    modifier = Modifier.padding(vertical = 8.dp)
                                ) {
                                    Text(
                                        p,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = if (isSel) Color.White else Color(0xFF475569)
                                    )
                                }
                            }
                        }
                    }
                }

                // 3. SUBJECT / TOPIC INPUT
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("SUBJECT / TOPIC", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B), letterSpacing = 0.5.sp)
                    OutlinedTextField(
                        value = ticketSubjectInput,
                        onValueChange = { ticketSubjectInput = it },
                        placeholder = { Text("e.g. Query regarding DSC signature in MCA filing", fontSize = 12.sp, color = Color(0xFF94A3B8)) },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        singleLine = true
                    )
                }

                // 4. DETAILED EXPLANATION INPUT
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("DETAILED EXPLANATION", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B), letterSpacing = 0.5.sp)
                    OutlinedTextField(
                        value = ticketDescriptionInput,
                        onValueChange = { ticketDescriptionInput = it },
                        placeholder = { Text("Please describe what you need assistance with in detail...", fontSize = 12.sp, color = Color(0xFF94A3B8)) },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(100.dp),
                        shape = RoundedCornerShape(12.dp)
                    )
                }

                // Action Buttons Row
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    TextButton(
                        onClick = { showRaiseTicketSheet = false },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Cancel", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF64748B))
                    }

                    Button(
                        onClick = {
                            if (ticketSubjectInput.isBlank() || ticketDescriptionInput.isBlank()) {
                                Toast.makeText(context, "Please fill in subject and description", Toast.LENGTH_SHORT).show()
                                return@Button
                            }
                            isSubmittingTicket = true
                            scope.launch {
                                try {
                                    val req = CreateTicketRequest(
                                        category = selectedCategoryForTicket,
                                        subject = ticketSubjectInput,
                                        description = ticketDescriptionInput,
                                        priority = ticketPriorityInput
                                    )
                                    val res = api.createTicket(req)
                                    if (res.isSuccessful) {
                                        Toast.makeText(context, "Support ticket created successfully!", Toast.LENGTH_SHORT).show()
                                        viewModel.refreshAllData(silent = true)
                                        showRaiseTicketSheet = false
                                        ticketSubjectInput = ""
                                        ticketDescriptionInput = ""
                                    } else {
                                        Toast.makeText(context, "Failed to submit ticket", Toast.LENGTH_SHORT).show()
                                    }
                                } catch (e: Exception) {
                                    Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
                                } finally {
                                    isSubmittingTicket = false
                                }
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier
                            .weight(1.5f)
                            .height(44.dp)
                    ) {
                        if (isSubmittingTicket) {
                            CircularProgressIndicator(color = Color.White, modifier = Modifier.size(18.dp))
                        } else {
                            Icon(Icons.Default.Send, contentDescription = null, tint = Color.White, modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("SUBMIT TICKET", fontSize = 11.sp, fontWeight = FontWeight.Black)
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))
            }
        }
    }
}

private data class CategoryConfig(
    val key: String,
    val title: String,
    val desc: String,
    val icon: androidx.compose.ui.graphics.vector.ImageVector
)
