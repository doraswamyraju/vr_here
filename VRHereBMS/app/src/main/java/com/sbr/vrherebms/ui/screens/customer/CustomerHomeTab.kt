package com.sbr.vrherebms.ui.screens.customer

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.ui.components.scaleOnPress
import com.sbr.vrherebms.ui.theme.*
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel

@Composable
private fun StatusBadge(status: String) {
    val (bgColor, textColor, borderColor) = when (status) {
        "Processing at Portal", "In Progress" -> Triple(Color(0xFFEFF6FF), Color(0xFF1D4ED8), Color(0xFFBFDBFE))
        "Waiting for Clarification", "In Review" -> Triple(Color(0xFFFAF5FF), Color(0xFF7E22CE), Color(0xFFE9D5FF))
        "Completed", "Approved" -> Triple(Color(0xFFECFDF5), Color(0xFF047857), Color(0xFFA7F3D0))
        "Pending Documents", "Documents Required" -> Triple(Color(0xFFFFFBEB), Color(0xFFB45309), Color(0xFFFDE68A))
        "Documents Verified" -> Triple(Color(0xFFECFDF5), Color(0xFF059669), Color(0xFFA7F3D0))
        else -> Triple(Color(0xFFF1F5F9), Color(0xFF334155), Color(0xFFE2E8F0))
    }

    Surface(
        color = bgColor,
        border = BorderStroke(1.dp, borderColor),
        shape = RoundedCornerShape(20.dp)
    ) {
        Text(
            text = status.uppercase(),
            fontSize = 9.sp,
            fontWeight = FontWeight.Black,
            color = textColor,
            letterSpacing = 0.5.sp,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
        )
    }
}

private data class QuickServiceItem(
    val id: Int,
    val name: String,
    val tag: String,
    val icon: ImageVector,
    val iconBg: Color,
    val iconTint: Color,
    val key: String,
    val url: String? = null
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomerHomeTab(
    viewModel: CustomerDashboardViewModel,
    userName: String,
    searchQuery: String,
    onSearchQueryChange: (String) -> Unit,
    onSelectTab: (String) -> Unit,
    onOpenProject: (String) -> Unit,
    onOpenLiveService: (String, String) -> Unit
) {
    val context = LocalContext.current
    var showSuggestions by remember { mutableStateOf(false) }

    val activeOrders = viewModel.orders.filter { it.status != "Completed" }
    val completedOrders = viewModel.orders.filter { it.status == "Completed" }
    val pendingActions = viewModel.orders.filter { order ->
        if (order.status == "Completed" || order.status == "Documents Verified" || order.status == "Processing at Portal") return@filter false
        if (order.status == "Waiting for Clarification") return@filter true
        if (order.status == "Pending Documents" || order.status == "Documents Required") {
            if (order.customerRequirements.isNotEmpty()) {
                return@filter order.customerRequirements.any { r ->
                    !r.isClientCompleted && r.uploadedDocumentUrl.isBlank() && r.documentUrl.isBlank() && r.clientValue.isBlank() && r.status != "Received" && r.status != "Verified"
                }
            }
            return@filter false
        }
        false
    }
    val unpaidOrders = viewModel.orders.filter { order ->
        order.status != "Completed" && (order.paymentStatus.equals("Pending", ignoreCase = true) || order.paymentStatus.equals("Partial", ignoreCase = true) || order.paymentStatus.equals("Unpaid", ignoreCase = true))
    }
    val totalOutstanding = unpaidOrders.sumOf { it.price.toLong() }
    val totalVolume = viewModel.orders.sumOf { it.price }

    val searchSuggestions = listOf(
        "Private Limited Company Registration",
        "Limited Liability Partnership (LLP)",
        "GST Registration",
        "GST Return Filing",
        "Income Tax Return",
        "MSME / Udyam Registration",
        "Trademark Registration",
        "FSSAI Food License",
        "ISO Certification",
        "Import Export Code (IEC)",
        "Company Annual Compliances",
        "Startup India DPIIT Registration"
    )

    val filteredSuggestions = remember(searchQuery) {
        if (searchQuery.isBlank()) emptyList()
        else searchSuggestions.filter { it.contains(searchQuery, ignoreCase = true) }.take(5)
    }

    val topServices = listOf(
        QuickServiceItem(1, "Pvt Ltd Setup", "MCA Approval", Icons.Default.Business, Color(0xFFFEF2F2), PrimaryRed, "Services", "https://vrhere.in/pvt-ltd-registration"),
        QuickServiceItem(2, "GST Filing", "Monthly / QRMP", Icons.Default.FactCheck, Color(0xFFECFDF5), Emerald500, "Services", "https://vrhere.in/gst-registration"),
        QuickServiceItem(3, "Income Tax", "ITR 1-7 Assessment", Icons.Default.Computer, Color(0xFFEFF6FF), Color(0xFF2563EB), "Services", "https://vrhere.in/income-tax-return"),
        QuickServiceItem(4, "Partnership", "Firm & Deed", Icons.Default.People, Color(0xFFFFFBEB), Amber500, "Services", "https://vrhere.in/partnership-firm"),
        QuickServiceItem(5, "ISO Standards", "9001 / 27001", Icons.Default.Security, Color(0xFFFAF5FF), Color(0xFF9333EA), "Services"),
        QuickServiceItem(6, "Audit Support", "Statutory & Tax", Icons.Default.AssignmentTurnedIn, Color(0xFFFFF1F2), Color(0xFFE11D48), "Support"),
        QuickServiceItem(7, "MSME Loans", "Bank DPR & CMA", Icons.Default.CurrencyRupee, Color(0xFFECFDF5), Color(0xFF059669), "Services"),
        QuickServiceItem(8, "ROC CCFS-2026", "Penalty Relief", Icons.Default.AutoAwesome, Color(0xFFFFF7ED), Color(0xFFEA580C), "Services", "https://vrhere.in/compliance-scheme-2026")
    )

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(top = 16.dp, bottom = 120.dp),
        verticalArrangement = Arrangement.spacedBy(18.dp)
    ) {
        // 1. TOP GREETING & SEARCH BAR WITH GLOWING BACKDROP
        item {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                // Greeting text
                Column {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(
                            text = "Welcome, ${userName.ifEmpty { "Valued Client" }}",
                            fontSize = 22.sp,
                            fontWeight = FontWeight.Black,
                            color = TextDark,
                            letterSpacing = (-0.5).sp
                        )
                        Text(text = "👋", fontSize = 20.sp)
                    }
                    Text(
                        text = "Here is an executive snapshot of your filings, compliance status, and vault.",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium,
                        color = TextMuted,
                        modifier = Modifier.padding(top = 2.dp)
                    )
                }

                // Glowing Search Input Container matching Web
                Box(modifier = Modifier.fillMaxWidth()) {
                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .shadow(6.dp, RoundedCornerShape(16.dp), ambientColor = PrimaryRed.copy(alpha = 0.15f), spotColor = PrimaryRed.copy(alpha = 0.25f)),
                        shape = RoundedCornerShape(16.dp),
                        color = Color.White,
                        border = BorderStroke(1.dp, BorderLight)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 14.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Default.Search,
                                contentDescription = "Search",
                                tint = PrimaryRed,
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            TextField(
                                value = searchQuery,
                                onValueChange = {
                                    onSearchQueryChange(it)
                                    showSuggestions = it.isNotBlank()
                                },
                                placeholder = {
                                    Text(
                                        "Search any service or filing...",
                                        fontSize = 12.5.sp,
                                        color = TextMuted
                                    )
                                },
                                colors = TextFieldDefaults.colors(
                                    focusedContainerColor = Color.Transparent,
                                    unfocusedContainerColor = Color.Transparent,
                                    disabledContainerColor = Color.Transparent,
                                    errorContainerColor = Color.Transparent,
                                    focusedIndicatorColor = Color.Transparent,
                                    unfocusedIndicatorColor = Color.Transparent,
                                    disabledIndicatorColor = Color.Transparent
                                ),
                                singleLine = true,
                                modifier = Modifier.weight(1f)
                            )
                            if (searchQuery.isNotBlank()) {
                                Button(
                                    onClick = {
                                        onSelectTab("Services")
                                        showSuggestions = false
                                    },
                                    colors = ButtonDefaults.buttonColors(containerColor = PrimaryRed),
                                    shape = RoundedCornerShape(8.dp),
                                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                                ) {
                                    Text("FIND", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color.White)
                                }
                            }
                        }
                    }
                }

                // Autocomplete Suggestions Dropdown
                if (showSuggestions && filteredSuggestions.isNotEmpty()) {
                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .shadow(12.dp, RoundedCornerShape(16.dp)),
                        shape = RoundedCornerShape(16.dp),
                        color = Color.White,
                        border = BorderStroke(1.dp, BorderLight)
                    ) {
                        Column(modifier = Modifier.padding(vertical = 6.dp)) {
                            filteredSuggestions.forEach { suggestion ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            val liveMap = mapOf(
                                                "Private Limited Company Registration" to Pair("Private Limited Registration", "https://vrhere.in/pvt-ltd-registration"),
                                                "Limited Liability Partnership (LLP)" to Pair("Partnership Firm", "https://vrhere.in/partnership-firm"),
                                                "GST Registration" to Pair("GST Registration", "https://vrhere.in/gst-registration"),
                                                "Income Tax Return" to Pair("Income Tax Return", "https://vrhere.in/income-tax-return"),
                                                "Company Annual Compliances" to Pair("CCFS-2026 Scheme", "https://vrhere.in/compliance-scheme-2026")
                                            )
                                            val matched = liveMap[suggestion]
                                            if (matched != null) {
                                                onOpenLiveService(matched.first, matched.second)
                                            } else {
                                                onSearchQueryChange(suggestion)
                                                onSelectTab("Services")
                                            }
                                            showSuggestions = false
                                        }
                                        .padding(horizontal = 16.dp, vertical = 10.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = suggestion,
                                        fontSize = 12.5.sp,
                                        fontWeight = FontWeight.SemiBold,
                                        color = TextDark
                                    )
                                    Icon(
                                        imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                                        contentDescription = null,
                                        tint = PrimaryRed,
                                        modifier = Modifier.size(14.dp)
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. 4-KPI STAT CARDS (EXECUTIVE OVERVIEW) MATCHING WEB 1:1
        item {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    // KPI 1: Active Orders
                    Surface(
                        modifier = Modifier
                            .weight(1f)
                            .scaleOnPress()
                            .clickable { onSelectTab("Orders") },
                        shape = RoundedCornerShape(18.dp),
                        color = Color.White,
                        border = BorderStroke(1.dp, BorderLight),
                        shadowElevation = 1.dp
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("ACTIVE ORDERS", fontSize = 9.sp, fontWeight = FontWeight.Black, color = TextMuted, letterSpacing = 0.5.sp)
                                Box(
                                    modifier = Modifier
                                        .size(30.dp)
                                        .background(PrimaryRed.copy(alpha = 0.10f), RoundedCornerShape(8.dp)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(Icons.Default.Work, contentDescription = null, tint = PrimaryRed, modifier = Modifier.size(15.dp))
                                }
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.Bottom
                            ) {
                                Text("${activeOrders.size}", fontSize = 22.sp, fontWeight = FontWeight.Black, color = TextDark)
                                Text("Track →", fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = PrimaryRed)
                            }
                            Text("In-progress filings", fontSize = 10.sp, color = TextMuted, modifier = Modifier.padding(top = 2.dp))
                        }
                    }

                    // KPI 2: Action Needed
                    val hasPending = pendingActions.isNotEmpty()
                    Surface(
                        modifier = Modifier
                            .weight(1f)
                            .scaleOnPress()
                            .clickable { onSelectTab("Orders") },
                        shape = RoundedCornerShape(18.dp),
                        color = if (hasPending) Color(0xFFFFF1F2) else Color.White,
                        border = BorderStroke(1.dp, if (hasPending) Color(0xFFFECDD3) else BorderLight),
                        shadowElevation = 1.dp
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    "ACTION NEEDED",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Black,
                                    color = if (hasPending) Color(0xFFE11D48) else TextMuted,
                                    letterSpacing = 0.5.sp
                                )
                                Box(
                                    modifier = Modifier
                                        .size(30.dp)
                                        .background(if (hasPending) Color(0xFFFFE4E6) else BgInput, RoundedCornerShape(8.dp)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        Icons.Default.Warning,
                                        contentDescription = null,
                                        tint = if (hasPending) Color(0xFFE11D48) else TextMuted,
                                        modifier = Modifier.size(15.dp)
                                    )
                                }
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.Bottom
                            ) {
                                Text(
                                    "${pendingActions.size}",
                                    fontSize = 22.sp,
                                    fontWeight = FontWeight.Black,
                                    color = if (hasPending) Color(0xFFBE123C) else TextDark
                                )
                                Text(
                                    "Upload →",
                                    fontSize = 10.5.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = if (hasPending) Color(0xFFE11D48) else TextMuted
                                )
                            }
                            Text("Pending proofs", fontSize = 10.sp, color = TextMuted, modifier = Modifier.padding(top = 2.dp))
                        }
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    // KPI 3: Digital Vault
                    Surface(
                        modifier = Modifier
                            .weight(1f)
                            .scaleOnPress()
                            .clickable { onSelectTab("Vault") },
                        shape = RoundedCornerShape(18.dp),
                        color = Color.White,
                        border = BorderStroke(1.dp, BorderLight),
                        shadowElevation = 1.dp
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("DIGITAL VAULT", fontSize = 9.sp, fontWeight = FontWeight.Black, color = TextMuted, letterSpacing = 0.5.sp)
                                Box(
                                    modifier = Modifier
                                        .size(30.dp)
                                        .background(Emerald500.copy(alpha = 0.10f), RoundedCornerShape(8.dp)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(Icons.Default.Folder, contentDescription = null, tint = Emerald500, modifier = Modifier.size(15.dp))
                                }
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.Bottom
                            ) {
                                val vaultCount = if (completedOrders.isNotEmpty()) completedOrders.size * 3 + 8 else 8
                                Text("$vaultCount", fontSize = 22.sp, fontWeight = FontWeight.Black, color = TextDark)
                                Text("Vault →", fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = Emerald500)
                            }
                            Text("Verified documents", fontSize = 10.sp, color = TextMuted, modifier = Modifier.padding(top = 2.dp))
                        }
                    }

                    // KPI 4: Total Portfolio / Due Balance
                    val hasDue = totalOutstanding > 0
                    Surface(
                        modifier = Modifier
                            .weight(1f)
                            .scaleOnPress()
                            .clickable { onSelectTab("Invoices") },
                        shape = RoundedCornerShape(18.dp),
                        color = if (hasDue) Color(0xFFFFFBEB) else Color.White,
                        border = BorderStroke(1.dp, if (hasDue) Color(0xFFFDE68A) else BorderLight),
                        shadowElevation = 1.dp
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    if (hasDue) "DUE BALANCE" else "TOTAL PORTFOLIO",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Black,
                                    color = if (hasDue) Amber500 else TextMuted,
                                    letterSpacing = 0.5.sp
                                )
                                Box(
                                    modifier = Modifier
                                        .size(30.dp)
                                        .background(if (hasDue) Color(0xFFFEF3C7) else Color(0xFF2563EB).copy(alpha = 0.10f), RoundedCornerShape(8.dp)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        Icons.Default.CurrencyRupee,
                                        contentDescription = null,
                                        tint = if (hasDue) Amber500 else Color(0xFF2563EB),
                                        modifier = Modifier.size(15.dp)
                                    )
                                }
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.Bottom
                            ) {
                                if (hasDue) {
                                    Text("₹${totalOutstanding}", fontSize = 20.sp, fontWeight = FontWeight.Black, color = Color(0xFF92400E))
                                    Text("Pay →", fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = Amber500)
                                } else {
                                    val volumeK = (totalVolume / 1000.0)
                                    Text("₹${"%.1f".format(volumeK)}k", fontSize = 22.sp, fontWeight = FontWeight.Black, color = TextDark)
                                    Text("Bills →", fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = Color(0xFF2563EB))
                                }
                            }
                            Text(
                                if (hasDue) "${unpaidOrders.size} pending payment(s)" else "Settled volume",
                                fontSize = 10.sp,
                                color = TextMuted,
                                modifier = Modifier.padding(top = 2.dp)
                            )
                        }
                    }
                }
            }
        }

        // 3. ENTERPRISE CLIENT HUB HERO BANNER MATCHING WEB 1:1
        item {
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .shadow(12.dp, RoundedCornerShape(24.dp), ambientColor = Color.Black.copy(alpha = 0.2f)),
                shape = RoundedCornerShape(24.dp),
                color = DarkSlate,
                border = BorderStroke(1.dp, Color.White.copy(alpha = 0.12f))
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Surface(
                            color = PrimaryRed.copy(alpha = 0.25f),
                            border = BorderStroke(1.dp, PrimaryRed.copy(alpha = 0.4f)),
                            shape = RoundedCornerShape(20.dp)
                        ) {
                            Text(
                                text = "ENTERPRISE CLIENT HUB",
                                fontSize = 9.5.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFFFF8080),
                                letterSpacing = 0.8.sp,
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                            )
                        }

                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.CheckCircle,
                                contentDescription = null,
                                tint = Emerald500,
                                modifier = Modifier.size(13.dp)
                            )
                            Text(
                                text = "Real-Time MCA Sync",
                                fontSize = 10.5.sp,
                                fontWeight = FontWeight.Bold,
                                color = Slate400
                            )
                        }
                    }

                    Text(
                        text = "Manage Filings, Upload Vault Docs & Track Milestones",
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Black,
                        color = Color.White,
                        lineHeight = 22.sp
                    )

                    Text(
                        text = "All filings and compliance submissions are managed directly by your assigned dedicated advisor and operations team.",
                        fontSize = 11.5.sp,
                        color = Slate400,
                        lineHeight = 16.sp
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Button(
                            onClick = { onSelectTab("Orders") },
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryRed),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier
                                .weight(1f)
                                .scaleOnPress(),
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 10.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Text("View Pipeline (${activeOrders.size})", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color.White)
                                Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = null, modifier = Modifier.size(13.dp))
                            }
                        }

                        Button(
                            onClick = { onSelectTab("Services") },
                            colors = ButtonDefaults.buttonColors(containerColor = Color.White.copy(alpha = 0.12f)),
                            border = BorderStroke(1.dp, Color.White.copy(alpha = 0.2f)),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.scaleOnPress(),
                            contentPadding = PaddingValues(horizontal = 14.dp, vertical = 10.dp)
                        ) {
                            Text("Catalog", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        }
                    }
                }
            }
        }

        // 3.5 PENDING INVOICES & OUTSTANDING BALANCE ATTENTION CARD
        if (unpaidOrders.isNotEmpty()) {
            item {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(20.dp),
                    color = Color(0xFFFEF2F2),
                    border = BorderStroke(1.dp, Color(0xFFFECDD3))
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
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
                                        .size(36.dp)
                                        .background(PrimaryRed, RoundedCornerShape(10.dp)),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(Icons.Default.AccountBalanceWallet, contentDescription = null, tint = Color.White, modifier = Modifier.size(18.dp))
                                }
                                Column {
                                    Text(
                                        text = "Pending Invoices & Payment Due",
                                        fontSize = 13.sp,
                                        fontWeight = FontWeight.Black,
                                        color = Color(0xFF991B1B)
                                    )
                                    Text(
                                        text = "Total Outstanding: ₹${totalOutstanding}",
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = PrimaryRed
                                    )
                                }
                            }
                        }

                        unpaidOrders.take(3).forEach { order ->
                            val balanceDue = order.price.toLong()
                            Surface(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { onOpenProject(order.id) },
                                shape = RoundedCornerShape(14.dp),
                                color = Color.White,
                                border = BorderStroke(1.dp, Color(0xFFFEE2E2))
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(order.serviceName, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = TextDark, maxLines = 1)
                                        Text("Balance Due: ₹$balanceDue", fontSize = 10.5.sp, fontWeight = FontWeight.Black, color = PrimaryRed)
                                    }
                                    Button(
                                        onClick = { onOpenProject(order.id) },
                                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryRed),
                                        shape = RoundedCornerShape(10.dp),
                                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                                    ) {
                                        Text("Pay ₹$balanceDue", fontSize = 10.5.sp, fontWeight = FontWeight.Black, color = Color.White)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 4. ACTION ITEMS REQUIRING ATTENTION (IF ANY)
        if (pendingActions.isNotEmpty()) {
            item {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(20.dp),
                    color = Color(0xFFFFFBEB),
                    border = BorderStroke(1.dp, Color(0xFFFDE68A))
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(36.dp)
                                    .background(Amber500, RoundedCornerShape(10.dp)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(Icons.Default.Warning, contentDescription = null, tint = Color.Black, modifier = Modifier.size(18.dp))
                            }
                            Column {
                                Text(
                                    text = "Action Items Require Attention",
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFF78350F)
                                )
                                Text(
                                    text = "${pendingActions.size} order(s) waiting for document uploads or clarification.",
                                    fontSize = 10.5.sp,
                                    color = Color(0xFF92400E)
                                )
                            }
                        }

                        pendingActions.take(2).forEach { order ->
                            Surface(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { onOpenProject(order.id) },
                                shape = RoundedCornerShape(12.dp),
                                color = Color.White,
                                border = BorderStroke(1.dp, Color(0xFFFDE68A))
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(order.serviceName, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = TextDark)
                                        Text(order.status, fontSize = 10.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFFB45309))
                                    }
                                    Button(
                                        onClick = { onOpenProject(order.id) },
                                        colors = ButtonDefaults.buttonColors(containerColor = Amber500),
                                        shape = RoundedCornerShape(8.dp),
                                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                                    ) {
                                        Text("Take Action →", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color.Black)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 5. ACTIVE OPERATIONAL PIPELINE SNAPSHOT
        item {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "Active Operational Pipeline",
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Black,
                            color = TextDark
                        )
                        Text(
                            text = "Live stage progress for ongoing filings",
                            fontSize = 11.sp,
                            color = TextMuted
                        )
                    }

                    Text(
                        text = "All Orders →",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = PrimaryRed,
                        modifier = Modifier
                            .clickable { onSelectTab("Orders") }
                            .scaleOnPress()
                    )
                }

                if (activeOrders.isEmpty()) {
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(18.dp),
                        color = Color.White,
                        border = BorderStroke(1.dp, BorderLight)
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(24.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(44.dp)
                                    .background(BgInput, CircleShape),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(Icons.Default.Work, contentDescription = null, tint = TextMuted, modifier = Modifier.size(20.dp))
                            }
                            Text("No Active Engagements", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = TextDark)
                            Text(
                                "Explore our catalog to start a new company incorporation, GST, or compliance filing.",
                                fontSize = 11.sp,
                                color = TextMuted,
                                textAlign = TextAlign.Center
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Button(
                                onClick = { onSelectTab("Services") },
                                colors = ButtonDefaults.buttonColors(containerColor = DarkSlate),
                                shape = RoundedCornerShape(10.dp)
                            ) {
                                Text("Browse Services", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color.White)
                            }
                        }
                    }
                } else {
                    activeOrders.take(3).forEach { proj ->
                        val progress = getStatusProgress(proj.status)
                        Surface(
                            modifier = Modifier
                                .fillMaxWidth()
                                .scaleOnPress()
                                .clickable { onOpenProject(proj.id) },
                            shape = RoundedCornerShape(18.dp),
                            color = Color.White,
                            border = BorderStroke(1.dp, BorderLight),
                            shadowElevation = 1.dp
                        ) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.Top
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = proj.serviceName,
                                            fontSize = 13.5.sp,
                                            fontWeight = FontWeight.Black,
                                            color = TextDark,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                        Text(
                                            text = proj.packageName.ifEmpty { "Standard Execution" },
                                            fontSize = 10.5.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = TextMuted
                                        )
                                    }
                                    StatusBadge(status = proj.status)
                                }

                                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Text("MILESTONE PROGRESS", fontSize = 9.sp, fontWeight = FontWeight.Black, color = TextMuted, letterSpacing = 0.5.sp)
                                        Text("$progress%", fontSize = 10.5.sp, fontWeight = FontWeight.Black, color = PrimaryRed)
                                    }
                                    LinearProgressIndicator(
                                        progress = { progress / 100f },
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .height(5.dp)
                                            .clip(CircleShape),
                                        color = PrimaryRed,
                                        trackColor = BgInput
                                    )
                                }

                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = "ID: #${proj.id.takeLast(6).uppercase()}",
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = TextMuted
                                    )
                                    Text(
                                        text = "Details →",
                                        fontSize = 10.5.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = PrimaryRed
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        // 6. QUICK ACTION LAUNCHPAD (8 SERVICES BENTO GRID) MATCHING WEB 1:1
        item {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                color = Color.White,
                border = BorderStroke(1.dp, BorderLight),
                shadowElevation = 1.dp
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text("Quick Action Launchpad", fontSize = 15.sp, fontWeight = FontWeight.Black, color = TextDark)
                            Text("One-click jump to frequent requirements", fontSize = 11.sp, color = TextMuted)
                        }
                        Text(
                            "Catalog →",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = PrimaryRed,
                            modifier = Modifier
                                .clickable { onSelectTab("Services") }
                                .scaleOnPress()
                        )
                    }

                    // 4x2 Grid Layout
                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        for (row in 0 until 2) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                for (col in 0 until 4) {
                                    val idx = row * 4 + col
                                    if (idx < topServices.size) {
                                        val service = topServices[idx]
                                        Surface(
                                            modifier = Modifier
                                                .weight(1f)
                                                .scaleOnPress()
                                                .clickable {
                                                    if (service.url != null) {
                                                        onOpenLiveService(service.name, service.url)
                                                    } else {
                                                        onSelectTab(service.key)
                                                    }
                                                },
                                            shape = RoundedCornerShape(14.dp),
                                            color = BgLight,
                                            border = BorderStroke(1.dp, BorderLight)
                                        ) {
                                            Column(
                                                modifier = Modifier
                                                    .fillMaxWidth()
                                                    .padding(vertical = 12.dp, horizontal = 4.dp),
                                                horizontalAlignment = Alignment.CenterHorizontally,
                                                verticalArrangement = Arrangement.Center
                                            ) {
                                                Box(
                                                    modifier = Modifier
                                                        .size(42.dp)
                                                        .background(service.iconBg, RoundedCornerShape(12.dp)),
                                                    contentAlignment = Alignment.Center
                                                ) {
                                                    Icon(
                                                        imageVector = service.icon,
                                                        contentDescription = service.name,
                                                        tint = service.iconTint,
                                                        modifier = Modifier.size(20.dp)
                                                    )
                                                }
                                                Spacer(modifier = Modifier.height(6.dp))
                                                Text(
                                                    text = service.name,
                                                    fontSize = 10.sp,
                                                    fontWeight = FontWeight.Black,
                                                    color = TextDark,
                                                    textAlign = TextAlign.Center,
                                                    maxLines = 1,
                                                    overflow = TextOverflow.Ellipsis
                                                )
                                                Text(
                                                    text = service.tag,
                                                    fontSize = 8.5.sp,
                                                    fontWeight = FontWeight.Medium,
                                                    color = TextMuted,
                                                    textAlign = TextAlign.Center,
                                                    maxLines = 1,
                                                    overflow = TextOverflow.Ellipsis
                                                )
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

        // 7. DEDICATED ADVISOR CARD MATCHING WEB 1:1
        item {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(22.dp),
                color = DarkSlate,
                border = BorderStroke(1.dp, Color.White.copy(alpha = 0.12f)),
                shadowElevation = 2.dp
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "DEDICATED ADVISOR",
                            fontSize = 9.5.sp,
                            fontWeight = FontWeight.Black,
                            color = Slate400,
                            letterSpacing = 0.8.sp
                        )
                        Surface(
                            color = Emerald500.copy(alpha = 0.20f),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Text(
                                "Available",
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Black,
                                color = Emerald500,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                            )
                        }
                    }

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(44.dp)
                                .background(
                                    Brush.linearGradient(listOf(Indigo500, Color(0xFF6366F1))),
                                    CircleShape
                                ),
                            contentAlignment = Alignment.Center
                        ) {
                            Text("CA", color = Color.White, fontWeight = FontWeight.Black, fontSize = 14.sp)
                        }
                        Column {
                            Text("Dedicated CA Advisory Team", fontSize = 13.5.sp, fontWeight = FontWeight.Bold, color = Color.White)
                            Text("Senior Chartered Accountant", fontSize = 11.sp, color = Slate400)
                        }
                    }

                    Text(
                        "Need priority clarification on your filing or requirements? Reach your dedicated advisor directly.",
                        fontSize = 11.5.sp,
                        color = Slate400,
                        lineHeight = 15.sp
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Button(
                            onClick = {
                                try {
                                    val intent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:918008530606"))
                                    context.startActivity(intent)
                                } catch (e: Exception) {
                                    Toast.makeText(context, "Dialer not available", Toast.LENGTH_SHORT).show()
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color.White.copy(alpha = 0.12f)),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier
                                .weight(1f)
                                .scaleOnPress(),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Icon(Icons.Default.Phone, contentDescription = null, tint = Color.White, modifier = Modifier.size(13.dp))
                                Text("Call Advisor", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color.White)
                            }
                        }

                        Button(
                            onClick = {
                                try {
                                    val url = "https://wa.me/918008530606"
                                    val i = Intent(Intent.ACTION_VIEW, Uri.parse(url))
                                    context.startActivity(i)
                                } catch (e: Exception) {
                                    Toast.makeText(context, "WhatsApp not available", Toast.LENGTH_SHORT).show()
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF22C55E)),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier
                                .weight(1f)
                                .scaleOnPress(),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp)
                        ) {
                            Text("WhatsApp", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        }
                    }
                }
            }
        }

        // 8. STATUTORY COMPLIANCE CALENDAR MATCHING WEB 1:1
        item {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(22.dp),
                color = Color.White,
                border = BorderStroke(1.dp, BorderLight),
                shadowElevation = 1.dp
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Icon(Icons.Default.CalendarMonth, contentDescription = null, tint = PrimaryRed, modifier = Modifier.size(16.dp))
                            Text("Compliance Calendar", fontSize = 13.sp, fontWeight = FontWeight.Black, color = TextDark)
                        }
                        Text("March 2026", fontSize = 10.5.sp, fontWeight = FontWeight.Bold, color = TextMuted)
                    }

                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        // Compliance 1
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            color = BgLight,
                            border = BorderStroke(1.dp, BorderLight)
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 12.dp, vertical = 10.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column {
                                    Text("GST-3B Filing", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = TextDark)
                                    Text("Monthly Return", fontSize = 10.sp, color = TextMuted)
                                }
                                Surface(
                                    color = Color(0xFFFEF2F2),
                                    border = BorderStroke(1.dp, Color(0xFFFECACA)),
                                    shape = RoundedCornerShape(6.dp)
                                ) {
                                    Text("20th Mar", fontSize = 10.sp, fontWeight = FontWeight.Black, color = PrimaryRed, modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                                }
                            }
                        }

                        // Compliance 2
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            color = BgLight,
                            border = BorderStroke(1.dp, BorderLight)
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 12.dp, vertical = 10.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column {
                                    Text("Advance Tax Q4", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = TextDark)
                                    Text("Direct Tax Installment", fontSize = 10.sp, color = TextMuted)
                                }
                                Surface(
                                    color = Color(0xFFFFFBEB),
                                    border = BorderStroke(1.dp, Color(0xFFFDE68A)),
                                    shape = RoundedCornerShape(6.dp)
                                ) {
                                    Text("15th Mar", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Amber500, modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                                }
                            }
                        }

                        // Compliance 3
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            color = BgLight,
                            border = BorderStroke(1.dp, BorderLight)
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 12.dp, vertical = 10.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column {
                                    Text("CCFS-2026 Amnesty", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = TextDark)
                                    Text("ROC Late Filing Waiver", fontSize = 10.sp, color = TextMuted)
                                }
                                Surface(
                                    color = Color(0xFFECFDF5),
                                    border = BorderStroke(1.dp, Color(0xFFA7F3D0)),
                                    shape = RoundedCornerShape(6.dp)
                                ) {
                                    Text("Active", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Emerald500, modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                                }
                            }
                        }
                    }
                }
            }
        }

        // 9. REFER & EARN REWARD CARD MATCHING WEB 1:1
        item {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(22.dp),
                color = Color(0xFFFFFBEB),
                border = BorderStroke(1.dp, Color(0xFFFDE68A)),
                shadowElevation = 1.dp
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(36.dp)
                                .background(Amber500, RoundedCornerShape(10.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.CardGiftcard, contentDescription = null, tint = Color.White, modifier = Modifier.size(20.dp))
                        }
                        Column {
                            Text("Refer & Earn ₹500", fontSize = 13.5.sp, fontWeight = FontWeight.Black, color = Color(0xFF78350F))
                            Text("Instant wallet credits per referral", fontSize = 10.5.sp, color = Color(0xFF92400E))
                        }
                    }

                    Text(
                        "Refer another founder for company registration or ISO certification and receive ₹500 credit on your next filing.",
                        fontSize = 11.5.sp,
                        color = Color(0xFF78350F).copy(alpha = 0.85f),
                        lineHeight = 15.sp
                    )

                    Button(
                        onClick = { onSelectTab("Referrals") },
                        colors = ButtonDefaults.buttonColors(containerColor = DarkSlate),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .scaleOnPress()
                    ) {
                        Text("Get Referral Link", fontSize = 11.5.sp, fontWeight = FontWeight.Bold, color = Color.White)
                    }
                }
            }
        }
    }
}
