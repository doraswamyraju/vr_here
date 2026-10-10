package com.sbr.vrherebms.ui.screens.admin.modules

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.animation.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
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
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.sbr.vrherebms.data.model.LeadNote
import com.sbr.vrherebms.data.model.LeadResponse
import com.sbr.vrherebms.data.model.UserResponse
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel
import java.net.URLEncoder

data class GroupedClient(
    val id: String,
    val customerName: String,
    val email: String,
    val phone: String,
    val isMember: Boolean,
    var status: String,
    val highestCategory: String,
    val totalPriceInterest: Double,
    val sources: List<String>,
    val services: List<ClientServiceIntent>,
    val leadIds: List<String>,
    val notes: List<LeadNote>,
    val lastActivityAt: String
)

data class ClientServiceIntent(
    val serviceName: String,
    val packageName: String?,
    val price: Double,
    val category: String,
    val clickCount: Int,
    val lastActivityAt: String
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminCrmScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var subTab by remember { mutableStateOf("Leads Pipeline") } // "Leads Pipeline", "Customer Directory"
    var searchQuery by remember { mutableStateOf("") }
    var activeCategoryTab by remember { mutableStateOf("ALL") }
    var statusFilter by remember { mutableStateOf("ALL") }
    var expandedClients by remember { mutableStateOf<Set<String>>(emptySet()) }
    var clientNoteInputs by remember { mutableStateOf<Map<String, String>>(emptyMap()) }
    var selectedCustomerForModal by remember { mutableStateOf<UserResponse?>(null) }

    // Group leads into grouped clients exactly matching iOS / Web logic
    val groupedClients = remember(adminViewModel.leads) {
        val map = mutableMapOf<String, GroupedClient>()
        for (lead in adminViewModel.leads) {
            val phone = (lead.phone ?: "").trim()
            val email = (lead.email ?: "").trim().lowercase()
            val name = (lead.customerName ?: "Guest Prospect").trim()

            val key = when {
                phone.isNotEmpty() && phone.length >= 7 -> "phone_$phone"
                email.isNotEmpty() && email.contains("@") -> "email_$email"
                else -> "lead_${lead.id}"
            }

            val svcIntent = ClientServiceIntent(
                serviceName = lead.serviceName ?: "General Inquiry",
                packageName = lead.packageName,
                price = lead.price ?: 0.0,
                category = lead.category ?: "PAGE_VIEW",
                clickCount = if (lead.category == "PACKAGE_CLICK") 1 else 0,
                lastActivityAt = lead.lastActivityAt ?: lead.createdAt ?: ""
            )

            val existing = map[key]
            if (existing != null) {
                val updatedServices = existing.services.toMutableList()
                if (updatedServices.none { it.serviceName == svcIntent.serviceName }) {
                    updatedServices.add(svcIntent)
                }
                val updatedNotes = existing.notes.toMutableList()
                lead.notes.forEach { n ->
                    if (updatedNotes.none { it.id == n.id }) {
                        updatedNotes.add(n)
                    }
                }
                val updatedLeadIds = existing.leadIds.toMutableList()
                if (!updatedLeadIds.contains(lead.id)) {
                    updatedLeadIds.add(lead.id)
                }

                val isHot = existing.highestCategory == "PACKAGE_CLICK" || lead.category == "PACKAGE_CLICK"

                map[key] = existing.copy(
                    customerName = if (existing.customerName == "Guest Prospect" && name != "Guest Prospect") name else existing.customerName,
                    email = if (existing.email.isEmpty()) email else existing.email,
                    phone = if (existing.phone.isEmpty()) phone else existing.phone,
                    highestCategory = if (isHot) "PACKAGE_CLICK" else "PAGE_VIEW",
                    totalPriceInterest = existing.totalPriceInterest + (lead.price ?: 0.0),
                    sources = (existing.sources + (lead.source ?: "web")).distinct(),
                    services = updatedServices,
                    leadIds = updatedLeadIds,
                    notes = updatedNotes,
                    lastActivityAt = lead.lastActivityAt ?: existing.lastActivityAt
                )
            } else {
                map[key] = GroupedClient(
                    id = key,
                    customerName = name,
                    email = email,
                    phone = phone,
                    isMember = email.isNotEmpty(),
                    status = lead.status ?: "NEW",
                    highestCategory = lead.category ?: "PAGE_VIEW",
                    totalPriceInterest = lead.price ?: 0.0,
                    sources = listOf(lead.source ?: "web"),
                    services = listOf(svcIntent),
                    leadIds = listOf(lead.id),
                    notes = lead.notes,
                    lastActivityAt = lead.lastActivityAt ?: lead.createdAt ?: ""
                )
            }
        }
        map.values.sortedByDescending { it.lastActivityAt }
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF8FAFC)),
        contentPadding = PaddingValues(bottom = 90.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // 1. Dark Command Header
        item {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A))
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(8.dp)
                                        .background(Color(0xFF22C55E), CircleShape)
                                )
                                Text(
                                    text = "LIVE INTENT TELEMETRY CRM",
                                    color = Color(0xFF38BDF8),
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Black,
                                    letterSpacing = 1.sp
                                )
                            }
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = if (subTab == "Leads Pipeline") "Leads & Intent Engine" else "Customer Directory",
                                color = Color.White,
                                fontSize = 22.sp,
                                fontWeight = FontWeight.Black
                            )
                        }

                        if (subTab == "Leads Pipeline") {
                            Button(
                                onClick = {
                                    expandedClients = if (expandedClients.size == groupedClients.size) {
                                        emptySet()
                                    } else {
                                        groupedClients.map { it.id }.toSet()
                                    }
                                },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = Color.White.copy(alpha = 0.15f),
                                    contentColor = Color.White
                                ),
                                shape = RoundedCornerShape(10.dp),
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp)
                            ) {
                                Text(
                                    text = if (expandedClients.size == groupedClients.size) "Collapse All" else "Expand All",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = if (subTab == "Leads Pipeline")
                            "All mobile and web interactions are aggregated by client profile. Review journey, package clicks, and unified notes."
                        else
                            "Track client profiles, lifetime project revenue, active engagements, and outstanding unpaid balances.",
                        color = Color(0xFF94A3B8),
                        fontSize = 12.sp,
                        lineHeight = 16.sp
                    )
                }
            }
        }

        // 2. Sub-Tab Switcher
        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                listOf("Leads Pipeline", "Customer Directory").forEach { tab ->
                    val isSelected = subTab == tab
                    Card(
                        modifier = Modifier
                            .weight(1f)
                            .clickable { subTab = tab },
                        shape = RoundedCornerShape(12.dp),
                        colors = CardDefaults.cardColors(
                            containerColor = if (isSelected) Color(0xFF6366F1) else Color.White
                        ),
                        border = BorderStroke(
                            1.dp,
                            if (isSelected) Color(0xFF6366F1) else Color(0xFFE2E8F0)
                        )
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 10.dp),
                            horizontalArrangement = Arrangement.Center,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = if (tab == "Leads Pipeline") Icons.Default.PersonSearch else Icons.Default.Business,
                                contentDescription = null,
                                tint = if (isSelected) Color.White else Color(0xFF475569),
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = tab,
                                color = if (isSelected) Color.White else Color(0xFF475569),
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
            }
        }

        // --- SUBTAB 1: LEADS PIPELINE ---
        if (subTab == "Leads Pipeline") {
            // Metrics cards horizontal row
            item {
                LazyRow(
                    modifier = Modifier.fillMaxWidth(),
                    contentPadding = PaddingValues(horizontal = 16.dp),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    item {
                        CrmMetricCard(
                            title = "UNIQUE CLIENTS",
                            value = "${groupedClients.size}",
                            sub = "${adminViewModel.leadStats?.total ?: adminViewModel.leads.size} Total Events",
                            icon = Icons.Default.Group,
                            color = Color(0xFF6366F1)
                        )
                    }
                    item {
                        CrmMetricCard(
                            title = "HOT INTENT",
                            value = "${adminViewModel.leadStats?.packageClicks ?: adminViewModel.leads.count { it.category == "PACKAGE_CLICK" }}",
                            sub = "Package Price Clicks",
                            icon = Icons.Default.LocalFireDepartment,
                            color = Color(0xFFEF4444)
                        )
                    }
                    item {
                        CrmMetricCard(
                            title = "BROWSING VIEWS",
                            value = "${adminViewModel.leadStats?.pageViews ?: adminViewModel.leads.count { it.category == "PAGE_VIEW" }}",
                            sub = "Service Page Views",
                            icon = Icons.Default.Visibility,
                            color = Color(0xFF3B82F6)
                        )
                    }
                    item {
                        CrmMetricCard(
                            title = "CONVERTED",
                            value = "${adminViewModel.leadStats?.converted ?: adminViewModel.leads.count { it.status == "CONVERTED" }}",
                            sub = "${adminViewModel.leadStats?.conversionRate ?: "0.0"}% Win Rate",
                            icon = Icons.Default.Verified,
                            color = Color(0xFF10B981)
                        )
                    }
                }
            }

            // Search Bar
            item {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    placeholder = { Text("Search by client, service, phone, or email...", fontSize = 12.sp) },
                    leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = Color(0xFF94A3B8)) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = Color.White,
                        unfocusedContainerColor = Color.White,
                        focusedBorderColor = Color(0xFF6366F1),
                        unfocusedBorderColor = Color(0xFFE2E8F0)
                    ),
                    singleLine = true
                )
            }

            // Category Filter Chips
            item {
                LazyRow(
                    modifier = Modifier.fillMaxWidth(),
                    contentPadding = PaddingValues(horizontal = 16.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    val catChips = listOf(
                        "ALL" to "All Leads",
                        "PACKAGE_CLICK" to "🔥 Hot Intent (Package Clicks)",
                        "PAGE_VIEW" to "👀 Browsing Views",
                        "CONVERTED" to "✅ Converted"
                    )
                    items(catChips) { (key, title) ->
                        val isSel = activeCategoryTab == key
                        Card(
                            modifier = Modifier.clickable { activeCategoryTab = key },
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(
                                containerColor = if (isSel) Color(0xFF6366F1) else Color.White
                            ),
                            border = BorderStroke(1.dp, if (isSel) Color(0xFF6366F1) else Color(0xFFE2E8F0))
                        ) {
                            Text(
                                text = title,
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                color = if (isSel) Color.White else Color(0xFF475569)
                            )
                        }
                    }
                }
            }

            // Status Filter Chips
            item {
                val statuses = listOf("ALL", "NEW", "CONTACTED", "IN_PROGRESS", "CONVERTED", "LOST")
                LazyRow(
                    modifier = Modifier.fillMaxWidth(),
                    contentPadding = PaddingValues(horizontal = 16.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(statuses) { st ->
                        val isSel = statusFilter == st
                        Card(
                            modifier = Modifier.clickable { statusFilter = st },
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(
                                containerColor = if (isSel) Color(0xFF6366F1) else Color.White
                            ),
                            border = BorderStroke(1.dp, if (isSel) Color(0xFF6366F1) else Color(0xFFE2E8F0))
                        ) {
                            Text(
                                text = st,
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                color = if (isSel) Color.White else Color(0xFF475569)
                            )
                        }
                    }
                }
            }

            // Filtered Grouped Clients List
            val filteredClients = groupedClients.filter { client ->
                val q = searchQuery.lowercase().trim()
                val matchesSearch = q.isEmpty() ||
                        client.customerName.lowercase().contains(q) ||
                        client.email.lowercase().contains(q) ||
                        client.phone.lowercase().contains(q) ||
                        client.services.any { it.serviceName.lowercase().contains(q) }

                val matchesCat = when (activeCategoryTab) {
                    "ALL" -> true
                    "CONVERTED" -> client.status.uppercase() == "CONVERTED"
                    else -> client.highestCategory == activeCategoryTab
                }

                val matchesStatus = if (statusFilter == "ALL") true else client.status.uppercase() == statusFilter

                matchesSearch && matchesCat && matchesStatus
            }

            if (filteredClients.isEmpty()) {
                item {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(40.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text("No telemetry leads found", color = Color(0xFF94A3B8), fontSize = 13.sp, fontWeight = FontWeight.Bold)
                    }
                }
            } else {
                items(filteredClients, key = { it.id }) { client ->
                    GroupedClientCard(
                        client = client,
                        isExpanded = expandedClients.contains(client.id),
                        noteInput = clientNoteInputs[client.id] ?: "",
                        employees = adminViewModel.employees,
                        onToggleExpand = {
                            expandedClients = if (expandedClients.contains(client.id)) {
                                expandedClients - client.id
                            } else {
                                expandedClients + client.id
                            }
                        },
                        onNoteInputChange = { newInput ->
                            clientNoteInputs = clientNoteInputs + (client.id to newInput)
                        },
                        onUpdateStatus = { newStatus ->
                            client.leadIds.firstOrNull()?.let { firstId ->
                                adminViewModel.updateLeadStatus(firstId, newStatus)
                            }
                        },
                        onAssignStaff = { empId ->
                            client.leadIds.firstOrNull()?.let { firstId ->
                                adminViewModel.assignLead(firstId, empId)
                            }
                        },
                        onAddNote = { noteText ->
                            client.leadIds.firstOrNull()?.let { firstId ->
                                adminViewModel.addLeadNote(firstId, noteText) {
                                    clientNoteInputs = clientNoteInputs + (client.id to "")
                                }
                            }
                        }
                    )
                }
            }
        }

        // --- SUBTAB 2: CUSTOMER DIRECTORY ---
        if (subTab == "Customer Directory") {
            val clientUsers = adminViewModel.users.filter { it.role.equals("client", ignoreCase = true) }

            // Search Bar
            item {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    placeholder = { Text("Search client accounts...", fontSize = 12.sp) },
                    leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = Color(0xFF94A3B8)) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = Color.White,
                        unfocusedContainerColor = Color.White,
                        focusedBorderColor = Color(0xFF6366F1),
                        unfocusedBorderColor = Color(0xFFE2E8F0)
                    ),
                    singleLine = true
                )
            }

            val filteredClientUsers = clientUsers.filter { c ->
                val q = searchQuery.lowercase().trim()
                if (q.isEmpty()) true else "${c.name} ${c.email} ${c.phone ?: ""} ${c.companyName ?: ""} ${c.gstin ?: ""}".lowercase().contains(q)
            }

            item {
                Text(
                    text = "CLIENT ACCOUNTS (${filteredClientUsers.size})",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF64748B),
                    modifier = Modifier.padding(horizontal = 16.dp)
                )
            }

            if (filteredClientUsers.isEmpty()) {
                item {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(40.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text("No client accounts match search criteria.", color = Color(0xFF94A3B8), fontSize = 13.sp, fontWeight = FontWeight.Bold)
                    }
                }
            } else {
                items(filteredClientUsers, key = { it.id }) { clientUser ->
                    CustomerDirectoryCard(
                        client = clientUser,
                        orders = adminViewModel.orders,
                        onViewProfile = { selectedCustomerForModal = clientUser }
                    )
                }
            }
        }
    }

    // Customer Detail Modal Sheet Dialog
    selectedCustomerForModal?.let { client ->
        CustomerDetailDialog(
            client = client,
            orders = adminViewModel.orders,
            onDismiss = { selectedCustomerForModal = null },
            onOpenWorkspace = { orderId ->
                selectedCustomerForModal = null
                adminViewModel.selectedOrderId = orderId
            }
        )
    }
}

@Composable
private fun CrmMetricCard(
    title: String,
    value: String,
    sub: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    color: Color
) {
    Card(
        modifier = Modifier.width(155.dp),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, color.copy(alpha = 0.2f))
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(title, fontSize = 9.sp, fontWeight = FontWeight.Black, color = color, letterSpacing = 0.5.sp)
                Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(14.dp))
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(value, fontSize = 22.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
            Spacer(modifier = Modifier.height(2.dp))
            Text(sub, fontSize = 10.sp, color = Color(0xFF64748B), fontWeight = FontWeight.Medium)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun GroupedClientCard(
    client: GroupedClient,
    isExpanded: Boolean,
    noteInput: String,
    employees: List<com.sbr.vrherebms.data.model.EmployeeResponse>,
    onToggleExpand: () -> Unit,
    onNoteInputChange: (String) -> Unit,
    onUpdateStatus: (String) -> Unit,
    onAssignStaff: (String) -> Unit,
    onAddNote: (String) -> Unit
) {
    val context = LocalContext.current
    var showStatusMenu by remember { mutableStateOf(false) }
    var showStaffMenu by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            // Top Row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.Top
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(
                            text = client.customerName,
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Black,
                            color = Color(0xFF1E293B)
                        )
                        if (client.isMember) {
                            Box(
                                modifier = Modifier
                                    .background(Color(0xFF6366F1).copy(alpha = 0.12f), RoundedCornerShape(4.dp))
                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                            ) {
                                Text("MEMBER", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF6366F1))
                            }
                        }
                    }
                    Spacer(modifier = Modifier.height(2.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        if (client.phone.isNotEmpty()) {
                            Text(client.phone, fontSize = 11.sp, color = Color(0xFF64748B))
                        }
                        if (client.email.isNotEmpty()) {
                            Text(client.email, fontSize = 11.sp, color = Color(0xFF64748B))
                        }
                    }
                }

                // Status dropdown badge
                Box {
                    val statusColor = when (client.status.uppercase()) {
                        "CONVERTED", "WON" -> Color(0xFF10B981)
                        "CONTACTED", "IN_PROGRESS" -> Color(0xFF3B82F6)
                        "NEW" -> Color(0xFFF59E0B)
                        "LOST" -> Color(0xFFEF4444)
                        else -> Color(0xFF64748B)
                    }

                    Box(
                        modifier = Modifier
                            .background(statusColor.copy(alpha = 0.12f), RoundedCornerShape(8.dp))
                            .clickable { showStatusMenu = true }
                            .padding(horizontal = 10.dp, vertical = 5.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text(client.status.uppercase(), fontSize = 9.sp, fontWeight = FontWeight.Black, color = statusColor)
                            Icon(Icons.Default.ArrowDropDown, contentDescription = null, tint = statusColor, modifier = Modifier.size(12.dp))
                        }
                    }

                    DropdownMenu(
                        expanded = showStatusMenu,
                        onDismissRequest = { showStatusMenu = false }
                    ) {
                        listOf("NEW", "CONTACTED", "IN_PROGRESS", "CONVERTED", "LOST").forEach { st ->
                            DropdownMenuItem(
                                text = { Text(st, fontWeight = FontWeight.Bold) },
                                onClick = {
                                    showStatusMenu = false
                                    onUpdateStatus(st)
                                }
                            )
                        }
                    }
                }
            }

            // Intent & Price Badge Row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    if (client.highestCategory == "PACKAGE_CLICK") {
                        Box(
                            modifier = Modifier
                                .background(Color(0xFFEF4444), RoundedCornerShape(6.dp))
                                .padding(horizontal = 8.dp, vertical = 4.dp)
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                Icon(Icons.Default.LocalFireDepartment, contentDescription = null, tint = Color.White, modifier = Modifier.size(11.dp))
                                Text("HOT INTENT", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color.White)
                            }
                        }
                    } else {
                        Box(
                            modifier = Modifier
                                .background(Color(0xFF3B82F6).copy(alpha = 0.12f), RoundedCornerShape(6.dp))
                                .padding(horizontal = 8.dp, vertical = 4.dp)
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                Icon(Icons.Default.Visibility, contentDescription = null, tint = Color(0xFF3B82F6), modifier = Modifier.size(11.dp))
                                Text("BROWSING", fontSize = 9.sp, fontWeight = FontWeight.Bold, color = Color(0xFF3B82F6))
                            }
                        }
                    }

                    if (client.totalPriceInterest > 0) {
                        Text(
                            text = "Interest: ₹${client.totalPriceInterest.toInt()}",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF10B981)
                        )
                    }
                }

                TextButton(
                    onClick = onToggleExpand,
                    contentPadding = PaddingValues(0.dp)
                ) {
                    Text("${client.services.size} Services", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFF6366F1))
                    Spacer(modifier = Modifier.width(4.dp))
                    Icon(
                        imageVector = if (isExpanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                        contentDescription = null,
                        tint = Color(0xFF6366F1),
                        modifier = Modifier.size(14.dp)
                    )
                }
            }

            // Direct Contact Action Buttons (WhatsApp, Call, Assign)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                if (client.phone.isNotEmpty()) {
                    Button(
                        onClick = {
                            val clean = client.phone.replace("+", "").replace(" ", "").trim()
                            val formatted = if (clean.length == 10) "91$clean" else clean
                            val topSvc = client.services.firstOrNull()?.serviceName ?: "VR Here Services"
                            val msg = "Hi ${client.customerName}, I noticed you were exploring *$topSvc* on VR Here. How can our CA & legal experts assist you today?"
                            val encoded = URLEncoder.encode(msg, "UTF-8")
                            val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://wa.me/$formatted?text=$encoded"))
                            context.startActivity(intent)
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF22C55E)),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.weight(1f),
                        contentPadding = PaddingValues(vertical = 6.dp)
                    ) {
                        Icon(Icons.Default.Chat, contentDescription = null, modifier = Modifier.size(12.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("WhatsApp", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    }

                    Button(
                        onClick = {
                            val intent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:${client.phone}"))
                            context.startActivity(intent)
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6)),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.weight(0.7f),
                        contentPadding = PaddingValues(vertical = 6.dp)
                    ) {
                        Icon(Icons.Default.Call, contentDescription = null, modifier = Modifier.size(12.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Call", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    }
                }

                Box(modifier = Modifier.weight(1f)) {
                    Button(
                        onClick = { showStaffMenu = true },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color(0xFFF1F5F9),
                            contentColor = Color(0xFF1E293B)
                        ),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth(),
                        contentPadding = PaddingValues(vertical = 6.dp)
                    ) {
                        Icon(Icons.Default.PersonAdd, contentDescription = null, modifier = Modifier.size(12.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Assign Staff", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    }

                    DropdownMenu(
                        expanded = showStaffMenu,
                        onDismissRequest = { showStaffMenu = false }
                    ) {
                        employees.forEach { emp ->
                            DropdownMenuItem(
                                text = { Text("${emp.name} (${emp.role})") },
                                onClick = {
                                    showStaffMenu = false
                                    onAssignStaff(emp.idVal)
                                }
                            )
                        }
                    }
                }
            }

            // Expanded Services & Follow-up Notes Section
            if (isExpanded) {
                Divider(color = Color(0xFFF1F5F9))

                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "EXPLORED SERVICES & PRICING",
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFF64748B)
                    )

                    client.services.forEach { svc ->
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFFF8FAFC)),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(10.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column {
                                    Text(svc.serviceName, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                                    if (!svc.packageName.isNullOrBlank()) {
                                        Text("Package: ${svc.packageName}", fontSize = 10.sp, color = Color(0xFF64748B))
                                    }
                                }
                                if (svc.price > 0) {
                                    Text("₹${svc.price.toInt()}", fontSize = 12.sp, fontWeight = FontWeight.Black, color = Color(0xFF10B981))
                                }
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "FOLLOW-UP NOTES",
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFF64748B)
                    )

                    // Preset Quick Chips
                    val presets = listOf("📞 Called - No Answer", "💬 Sent WhatsApp Quote", "🤝 Follow up Tomorrow", "📋 Requested KYC Docs", "✅ Ready to Order")
                    LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        items(presets) { preset ->
                            Card(
                                modifier = Modifier.clickable { onAddNote(preset) },
                                shape = RoundedCornerShape(6.dp),
                                colors = CardDefaults.cardColors(containerColor = Color(0xFFF1F5F9)),
                                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                            ) {
                                Text(
                                    text = preset,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFF1E293B)
                                )
                            }
                        }
                    }

                    // Custom Note Field
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        OutlinedTextField(
                            value = noteInput,
                            onValueChange = onNoteInputChange,
                            placeholder = { Text("Log custom followup note...", fontSize = 11.sp) },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(8.dp),
                            singleLine = true,
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedContainerColor = Color.White,
                                unfocusedContainerColor = Color.White
                            )
                        )
                        IconButton(
                            onClick = {
                                if (noteInput.isNotBlank()) {
                                    onAddNote(noteInput)
                                }
                            },
                            modifier = Modifier
                                .background(Color(0xFF6366F1), RoundedCornerShape(8.dp))
                                .size(40.dp)
                        ) {
                            Icon(Icons.Default.Send, contentDescription = null, tint = Color.White, modifier = Modifier.size(16.dp))
                        }
                    }

                    // Notes History
                    if (client.notes.isNotEmpty()) {
                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            client.notes.forEach { n ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .background(Color.White, RoundedCornerShape(8.dp))
                                        .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(8.dp))
                                        .padding(8.dp),
                                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                                    verticalAlignment = Alignment.Top
                                ) {
                                    Icon(Icons.Default.ChatBubble, contentDescription = null, tint = Color(0xFF6366F1), modifier = Modifier.size(12.dp).padding(top = 2.dp))
                                    Column {
                                        Text(n.text, fontSize = 11.sp, fontWeight = FontWeight.Medium, color = Color(0xFF1E293B))
                                        n.createdAt?.let { dt ->
                                            Text(dt, fontSize = 9.sp, color = Color(0xFF94A3B8))
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
}

@Composable
private fun CustomerDirectoryCard(
    client: UserResponse,
    orders: List<com.sbr.vrherebms.data.model.OrderResponse>,
    onViewProfile: () -> Unit
) {
    val clientPhone = client.phone ?: ""
    val clientOrders = remember(client, orders) {
        orders.filter {
            it.email.equals(client.email, ignoreCase = true) ||
                    (clientPhone.isNotEmpty() && it.phone == clientPhone) ||
                    it.clientName.equals(client.name, ignoreCase = true)
        }
    }
    val totalRevenue = clientOrders.sumOf { it.price }
    val activeOrders = clientOrders.count { it.status != "Completed" }
    var unpaidBalance = 0.0
    clientOrders.forEach { ord ->
        ord.invoices.filter { it.status == "Sent" }.forEach { inv ->
            unpaidBalance += inv.amount
        }
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(44.dp)
                            .background(
                                Brush.linearGradient(listOf(Color(0xFF6366F1), Color(0xFFA855F7))),
                                CircleShape
                            ),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = client.name.take(1).uppercase(),
                            color = Color.White,
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Black
                        )
                    }

                    Column {
                        Text(client.name, fontSize = 14.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                        Text(
                            text = "${client.email} • ${if (clientPhone.isEmpty()) "No Phone" else clientPhone}",
                            fontSize = 11.sp,
                            color = Color(0xFF64748B)
                        )
                        if (!client.companyName.isNullOrBlank()) {
                            Text(client.companyName, fontSize = 10.sp, fontWeight = FontWeight.Medium, color = Color(0xFF6366F1))
                        }
                    }
                }

                Button(
                    onClick = onViewProfile,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF6366F1).copy(alpha = 0.1f),
                        contentColor = Color(0xFF6366F1)
                    ),
                    shape = RoundedCornerShape(8.dp),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp)
                ) {
                    Text("View Profile", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }
            }

            Divider(color = Color(0xFFF1F5F9))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column {
                    Text("LIFETIME VALUE", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                    Text("₹${totalRevenue.toInt()}", fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color(0xFF10B981))
                }
                Column {
                    Text("ACTIVE ENGAGEMENTS", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                    Text("$activeOrders Active", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF3B82F6))
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text("UNPAID INVOICES", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                    Text("₹${unpaidBalance.toInt()}", fontSize = 13.sp, fontWeight = FontWeight.Black, color = if (unpaidBalance > 0) Color(0xFFEF4444) else Color(0xFF94A3B8))
                }
            }
        }
    }
}

@Composable
private fun CustomerDetailDialog(
    client: UserResponse,
    orders: List<com.sbr.vrherebms.data.model.OrderResponse>,
    onDismiss: () -> Unit,
    onOpenWorkspace: (String) -> Unit
) {
    val clientPhone = client.phone ?: ""
    val clientOrders = remember(client, orders) {
        orders.filter {
            it.email.equals(client.email, ignoreCase = true) ||
                    (clientPhone.isNotEmpty() && it.phone == clientPhone) ||
                    it.clientName.equals(client.name, ignoreCase = true)
        }
    }
    val totalRevenue = clientOrders.sumOf { it.price }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Card(
            modifier = Modifier
                .fillMaxWidth(0.95f)
                .fillMaxHeight(0.85f),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFFF8FAFC))
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(20.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Modal Header
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Customer Details", fontSize = 18.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = null, tint = Color(0xFF64748B))
                    }
                }

                // Profile Card
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    shape = RoundedCornerShape(16.dp),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(14.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(50.dp)
                                .background(
                                    Brush.linearGradient(listOf(Color(0xFF6366F1), Color(0xFFA855F7))),
                                    CircleShape
                                ),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = client.name.take(1).uppercase(),
                                color = Color.White,
                                fontSize = 20.sp,
                                fontWeight = FontWeight.Black
                            )
                        }

                        Column {
                            Text(client.name, fontSize = 16.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                            Text(client.email, fontSize = 12.sp, color = Color(0xFF64748B))
                            if (clientPhone.isNotEmpty()) {
                                Text(clientPhone, fontSize = 12.sp, color = Color(0xFF64748B))
                            }
                        }
                    }
                }

                // Lifetime Metrics Grid
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Card(
                        modifier = Modifier.weight(1f),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        shape = RoundedCornerShape(14.dp),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Text("Total Revenue", fontSize = 11.sp, color = Color(0xFF64748B))
                            Spacer(modifier = Modifier.height(4.dp))
                            Text("₹${totalRevenue.toInt()}", fontSize = 18.sp, fontWeight = FontWeight.Black, color = Color(0xFF10B981))
                        }
                    }

                    Card(
                        modifier = Modifier.weight(1f),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        shape = RoundedCornerShape(14.dp),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Text("Projects Count", fontSize = 11.sp, color = Color(0xFF64748B))
                            Spacer(modifier = Modifier.height(4.dp))
                            Text("${clientOrders.size} Orders", fontSize = 18.sp, fontWeight = FontWeight.Black, color = Color(0xFF6366F1))
                        }
                    }
                }

                // Projects & Engagements List
                Text("PROJECTS & ENGAGEMENTS", fontSize = 11.sp, fontWeight = FontWeight.Black, color = Color(0xFF64748B))

                if (clientOrders.isEmpty()) {
                    Text("No orders recorded for this client yet.", fontSize = 12.sp, color = Color(0xFF94A3B8), modifier = Modifier.padding(8.dp))
                } else {
                    clientOrders.forEach { ord ->
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            shape = RoundedCornerShape(12.dp),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(12.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column {
                                    Text(ord.serviceName, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                                    Text("₹${ord.price.toInt()} • Package: ${ord.packageName}", fontSize = 11.sp, color = Color(0xFF64748B))
                                }

                                Button(
                                    onClick = { onOpenWorkspace(ord.id) },
                                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6)),
                                    shape = RoundedCornerShape(6.dp),
                                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp)
                                ) {
                                    Text("Open Workspace", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
