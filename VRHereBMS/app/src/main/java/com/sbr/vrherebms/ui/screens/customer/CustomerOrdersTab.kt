package com.sbr.vrherebms.ui.screens.customer

import android.graphics.Bitmap
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.result.launch
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.local.SessionManager
import com.sbr.vrherebms.data.model.CreateTicketRequest
import com.sbr.vrherebms.data.model.CustomerRequirement
import com.sbr.vrherebms.data.remote.VRHereAPI
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel
import kotlinx.coroutines.launch
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomerOrdersTab(
    viewModel: CustomerDashboardViewModel,
    onSelectTab: (String) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val api = remember { VRHereAPI.getInstance(context) }
    val sessionManager = remember { SessionManager(context) }

    // Screen State
    var selectedOrderId by remember { mutableStateOf<String?>(null) }
    var selectedFilter by remember { mutableStateOf("all") } // "all" | "active" | "completed" | "action"

    // Sub-tab state inside Order Details view ('requirements' | 'documents' | 'financials')
    var currentDetailTab by remember { mutableStateOf("requirements") }

    // Requirement Sheet State
    var activeReq by remember { mutableStateOf<CustomerRequirement?>(null) }
    var detailText by remember { mutableStateOf("") }
    var notesText by remember { mutableStateOf("") }
    var showRequirementSheet by remember { mutableStateOf(false) }
    var isSubmittingReq by remember { mutableStateOf(false) }
    var reqFilter by remember { mutableStateOf("all") } // "all" | "pending" | "completed"

    // Vault Standard Document Selection Sheet State
    var showVaultSelectionSheet by remember { mutableStateOf(false) }

    // Support Query Modal State
    var showSupportModal by remember { mutableStateOf(false) }
    var querySubject by remember { mutableStateOf("") }
    var queryDescription by remember { mutableStateOf("") }
    var isSubmittingTicket by remember { mutableStateOf(false) }

    // Razorpay Payment Bottom Sheet State
    var showPaymentBottomSheet by remember { mutableStateOf(false) }

    val ordersList = viewModel.orders
    val selectedOrder = ordersList.find { it.id == selectedOrderId }

    // Requirement Document Upload Handlers
    fun submitRequirementPayload(body: Map<String, Any>) {
        if (selectedOrderId == null || activeReq == null) return
        isSubmittingReq = true
        scope.launch {
            try {
                val res = api.updateOrderRequirement(selectedOrderId!!, activeReq!!.id ?: "", body)
                if (res.isSuccessful) {
                    Toast.makeText(context, "Requirement submitted successfully!", Toast.LENGTH_SHORT).show()
                    viewModel.refreshAllData(silent = true)
                    showRequirementSheet = false
                    showVaultSelectionSheet = false
                } else {
                    Toast.makeText(context, "Submission failed: ${res.code()}", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_LONG).show()
            } finally {
                isSubmittingReq = false
            }
        }
    }

    fun uploadRequirementMultipart(part: okhttp3.MultipartBody.Part) {
        if (selectedOrderId == null || activeReq == null) return
        isSubmittingReq = true
        scope.launch {
            try {
                val reqIdBody = (activeReq!!.id ?: "").toRequestBody("text/plain".toMediaTypeOrNull())
                val res = api.uploadRequirementDocument(selectedOrderId!!, part, reqIdBody)
                if (res.isSuccessful) {
                    Toast.makeText(context, "Document uploaded successfully!", Toast.LENGTH_SHORT).show()
                    viewModel.refreshAllData(silent = true)
                    showRequirementSheet = false
                } else {
                    Toast.makeText(context, "Upload failed: ${res.code()}", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_LONG).show()
            } finally {
                isSubmittingReq = false
            }
        }
    }

    // Launchers for Requirement Document Pickers
    val reqFilePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null) {
            val part = uriToMultipartPart(context, uri)
            if (part != null) {
                uploadRequirementMultipart(part)
            } else {
                Toast.makeText(context, "Failed to process selected file", Toast.LENGTH_SHORT).show()
            }
        }
    }

    val reqCameraLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.TakePicturePreview()
    ) { bitmap: Bitmap? ->
        if (bitmap != null) {
            val part = bitmapToMultipartPart(context, bitmap)
            if (part != null) {
                uploadRequirementMultipart(part)
            } else {
                Toast.makeText(context, "Failed to process camera photo", Toast.LENGTH_SHORT).show()
            }
        }
    }

    // --- MAIN SCREEN CONTENT ---
    if (selectedOrder == null) {
        // ==================== LIST OF ORDERS VIEW ====================
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .background(Color(0xFFF8FAFC)),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            // Header Title & Filter Chips
            item {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text("My Service Orders", fontSize = 22.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                            Text("Track, fulfill requirements & download filing certificates", fontSize = 12.sp, color = Color(0xFF64748B))
                        }
                        Surface(
                            shape = CircleShape,
                            color = Color(0xFFFEF2F2),
                            modifier = Modifier.padding(4.dp)
                        ) {
                            Text("${ordersList.size}", fontSize = 12.sp, fontWeight = FontWeight.Black, color = Color(0xFFDC2626), modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp))
                        }
                    }

                    // Category Filter Pills
                    LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        val activeCount = ordersList.count { it.status != "Completed" }
                        val actionCount = ordersList.count { o -> o.customerRequirements.any { !it.isClientCompleted } }
                        val completedCount = ordersList.count { it.status == "Completed" }

                        val filters = listOf(
                            "all" to "All Orders (${ordersList.size})",
                            "active" to "Active ($activeCount)",
                            "action" to "Action Required ($actionCount)",
                            "completed" to "Completed ($completedCount)"
                        )
                        items(filters) { (key, label) ->
                            val isSelected = selectedFilter == key
                            Surface(
                                shape = RoundedCornerShape(12.dp),
                                color = if (isSelected) Color(0xFFDC2626) else Color.White,
                                border = BorderStroke(1.dp, if (isSelected) Color(0xFFDC2626) else Color(0xFFE2E8F0)),
                                modifier = Modifier
                                    .scaleOnPress()
                                    .clickable { selectedFilter = key }
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
            }

            // Filtered Orders List
            val filteredOrders = ordersList.filter { order ->
                when (selectedFilter) {
                    "active" -> order.status != "Completed"
                    "completed" -> order.status == "Completed"
                    "action" -> order.customerRequirements.any { !it.isClientCompleted }
                    else -> true
                }
            }

            if (filteredOrders.isEmpty()) {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(
                            modifier = Modifier
                                .padding(32.dp)
                                .fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Icon(Icons.Default.ReceiptLong, contentDescription = null, tint = Color.LightGray, modifier = Modifier.size(48.dp))
                            Text("No orders match selected filter", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = Color(0xFF64748B))
                            Button(
                                onClick = { onSelectTab("Services") },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                                shape = RoundedCornerShape(12.dp)
                            ) {
                                Text("Browse Services Catalog", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            } else {
                items(filteredOrders) { order ->
                    val pendingReqs = order.customerRequirements.count { !it.isClientCompleted }
                    val progress = getStatusProgress(order.status)

                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .scaleOnPress()
                            .clickable {
                                selectedOrderId = order.id
                                currentDetailTab = "requirements"
                            },
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            // Order ID & Status Header
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Surface(
                                        shape = RoundedCornerShape(6.dp),
                                        color = Color(0xFFF1F5F9)
                                    ) {
                                        Text("#${order.id.takeLast(8).uppercase()}", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF475569), modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                                    }
                                    if (pendingReqs > 0) {
                                        Surface(
                                            shape = RoundedCornerShape(6.dp),
                                            color = Color(0xFFFEF2F2)
                                        ) {
                                            Text("$pendingReqs Action Required", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFFDC2626), modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                                        }
                                    }
                                }
                                StatusBadgeWidget(status = order.status)
                            }

                            // Service Title & Price
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = order.serviceName.ifEmpty { "Business Filing Order" },
                                        fontSize = 15.sp,
                                        fontWeight = FontWeight.Black,
                                        color = Color(0xFF0F172A),
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    Text(
                                        text = "Package: ${order.packageName.ifEmpty { "Standard Professional" }}",
                                        fontSize = 11.sp,
                                        color = Color(0xFF64748B)
                                    )
                                }
                                Text("₹${order.price.toInt()}", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                            }

                            // Progress Bar
                            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("Filing Progress", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFF64748B))
                                    Text("$progress%", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFFDC2626))
                                }
                                LinearProgressIndicator(
                                    progress = { progress / 100f },
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .height(6.dp)
                                        .clip(RoundedCornerShape(3.dp)),
                                    color = Color(0xFFDC2626),
                                    trackColor = Color(0xFFF1F5F9)
                                )
                            }

                            // Card Footer
                            HorizontalDivider(color = Color(0xFFF1F5F9))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = if (order.updatedAt.length >= 10) "Updated: ${order.updatedAt.substring(0, 10)}" else "Active Order",
                                    fontSize = 11.sp,
                                    color = Color(0xFF94A3B8)
                                )
                                Text(
                                    text = "Manage Order ›",
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
    } else {
        // ==================== 1:1 ORDER DETAILS SCREEN ====================
        val order = selectedOrder
        val requirements = order.customerRequirements
        val pendingRequirements = requirements.filter { !it.isClientCompleted }
        val completedRequirements = requirements.filter { it.isClientCompleted }
        val filteredRequirements = when (reqFilter) {
            "pending" -> pendingRequirements
            "completed" -> completedRequirements
            else -> requirements
        }

        val reqProgressPercentage = if (requirements.isEmpty()) 100 else ((completedRequirements.size.toFloat() / requirements.size.toFloat()) * 100).toInt()
        val orderPayments = viewModel.payments.filter { p -> p.order?.id == order.id || p.serviceName.equals(order.serviceName, ignoreCase = true) }
        val totalPaid = orderPayments.filter { it.status == "Completed" || it.status == "Paid" }.sumOf { it.amount }
        val balance = (order.price - totalPaid).coerceAtLeast(0.0)

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .background(Color(0xFFF8FAFC)),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            // --- TOP NAVIGATION HEADER ---
            item {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        IconButton(
                            onClick = { selectedOrderId = null },
                            modifier = Modifier
                                .size(36.dp)
                                .background(Color.White, CircleShape)
                                .border(1.dp, Color(0xFFE2E8F0), CircleShape)
                        ) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = Color(0xFF0F172A), modifier = Modifier.size(18.dp))
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = order.serviceName,
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFF0F172A),
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Text(
                                text = "Order ID: #${order.id.takeLast(8).uppercase()} • ${order.packageName}",
                                fontSize = 11.sp,
                                color = Color(0xFF64748B)
                            )
                        }
                        StatusBadgeWidget(status = order.status)
                    }

                    // Quick Action Bar (Pay Balance / Ask Support)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        if (balance > 0) {
                            Button(
                                onClick = { showPaymentBottomSheet = true },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier.weight(1f),
                                contentPadding = PaddingValues(vertical = 8.dp)
                            ) {
                                Icon(Icons.Default.CreditCard, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Pay Balance ₹${balance.toInt()}", fontSize = 11.sp, fontWeight = FontWeight.Black)
                            }
                        }

                        OutlinedButton(
                            onClick = { showSupportModal = true },
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.weight(1f),
                            contentPadding = PaddingValues(vertical = 8.dp)
                        ) {
                            Icon(Icons.Default.HelpOutline, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Ask Support", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }

            // --- 5-PHASE TIMELINE STEPPER CARD ---
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                            Text("Filing Milestones Stepper", fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                            Text("${getStatusProgress(order.status)}% Complete", fontSize = 11.sp, fontWeight = FontWeight.Black, color = Color(0xFFDC2626))
                        }

                        LinearProgressIndicator(
                            progress = { getStatusProgress(order.status) / 100f },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(8.dp)
                                .clip(RoundedCornerShape(4.dp)),
                            color = Color(0xFFDC2626),
                            trackColor = Color(0xFFF1F5F9)
                        )

                        val phases = listOf("Pending Docs", "Verified", "Portal Processing", "Clarification", "Completed")
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            phases.forEachIndexed { idx, phaseName ->
                                val currentStep = when (order.status) {
                                    "Pending Documents" -> 0
                                    "Documents Verified" -> 1
                                    "Processing at Portal" -> 2
                                    "Waiting for Clarification" -> 3
                                    "Completed" -> 4
                                    else -> 0
                                }
                                val isDone = idx <= currentStep
                                Text(
                                    text = phaseName,
                                    fontSize = 8.sp,
                                    fontWeight = if (isDone) FontWeight.Black else FontWeight.Normal,
                                    color = if (isDone) Color(0xFF0F172A) else Color(0xFF94A3B8),
                                    textAlign = TextAlign.Center
                                )
                            }
                        }
                    }
                }
            }

            // --- DELIVERABLES READY ALERT BANNER ---
            if (order.adminDocuments.isNotEmpty() || !order.finalCertificateUrl.isNullOrEmpty()) {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFECFDF5)),
                        border = BorderStroke(1.dp, Color(0xFFA7F3D0))
                    ) {
                        Row(
                            modifier = Modifier.padding(14.dp).fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.weight(1f)) {
                                Icon(Icons.Default.Verified, contentDescription = null, tint = Color(0xFF047857), modifier = Modifier.size(24.dp))
                                Column {
                                    Text("Deliverables & Certificates Issued!", fontSize = 12.sp, fontWeight = FontWeight.Black, color = Color(0xFF064E3B))
                                    Text("Official documents are ready in your Vault", fontSize = 10.sp, color = Color(0xFF047857))
                                }
                            }
                            Button(
                                onClick = { currentDetailTab = "documents" },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF047857)),
                                shape = RoundedCornerShape(8.dp),
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                            ) {
                                Text("Go to Vault", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }

            // --- 3 SUB-TABS (Requirements | Vault | Financials) ---
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color.White, RoundedCornerShape(16.dp))
                        .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(16.dp))
                        .padding(4.dp)
                ) {
                    val tabs = listOf(
                        Triple("requirements", "Requirements (${pendingRequirements.size} pending)", pendingRequirements.size),
                        Triple("documents", "Vault (${order.adminDocuments.size + order.clientDocuments.size})", 0),
                        Triple("financials", "Financials", 0)
                    )

                    tabs.forEach { (key, label, badgeCount) ->
                        val isSelected = currentDetailTab == key
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .background(
                                    if (isSelected) Color(0xFFDC2626) else Color.Transparent,
                                    RoundedCornerShape(12.dp)
                                )
                                .clickable { currentDetailTab = key }
                                .padding(vertical = 10.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = label,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Black,
                                color = if (isSelected) Color.White else Color(0xFF64748B)
                            )
                        }
                    }
                }
            }

            // --- SUB-TAB 1: REQUIREMENTS & ACTION ITEMS ---
            if (currentDetailTab == "requirements") {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column {
                                    Text("Required Action Checklist", fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                    Text("$reqProgressPercentage% Completed (${completedRequirements.size}/${requirements.size})", fontSize = 11.sp, color = Color(0xFF64748B))
                                }

                                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                    listOf("pending" to "Pending", "completed" to "Done", "all" to "All").forEach { (key, label) ->
                                        val isSel = reqFilter == key
                                        Surface(
                                            shape = RoundedCornerShape(8.dp),
                                            color = if (isSel) Color(0xFF0F172A) else Color(0xFFF1F5F9),
                                            modifier = Modifier.clickable { reqFilter = key }
                                        ) {
                                            Text(
                                                label,
                                                fontSize = 10.sp,
                                                fontWeight = FontWeight.Bold,
                                                color = if (isSel) Color.White else Color(0xFF64748B),
                                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                                            )
                                        }
                                    }
                                }
                            }

                            if (filteredRequirements.isEmpty()) {
                                Text("No requirements in this category.", fontSize = 12.sp, color = Color(0xFF64748B), modifier = Modifier.padding(vertical = 10.dp))
                            } else {
                                filteredRequirements.forEach { req ->
                                    val isVerified = req.status == "Verified"
                                    val isSubmitted = req.status == "Received" || req.status == "Submitted" || req.isClientCompleted || !req.value.isNullOrEmpty()

                                    Card(
                                        shape = RoundedCornerShape(14.dp),
                                        colors = CardDefaults.cardColors(containerColor = Color(0xFFF8FAFC)),
                                        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                            Row(
                                                modifier = Modifier.fillMaxWidth(),
                                                horizontalArrangement = Arrangement.SpaceBetween,
                                                verticalAlignment = Alignment.Top
                                            ) {
                                                Column(modifier = Modifier.weight(1f)) {
                                                    Text(req.title, fontWeight = FontWeight.Black, fontSize = 13.sp, color = Color(0xFF0F172A))
                                                    Text(req.description, fontSize = 11.sp, color = Color(0xFF64748B))
                                                }
                                                Surface(
                                                    color = if (isVerified) Color(0xFFD1FAE5) else if (isSubmitted) Color(0xFFDBEAFE) else Color(0xFFFFE4E6),
                                                    shape = RoundedCornerShape(6.dp)
                                                ) {
                                                    Text(
                                                        text = if (isVerified) "VERIFIED" else if (isSubmitted) "SUBMITTED" else "ACTION REQD",
                                                        fontSize = 9.sp,
                                                        fontWeight = FontWeight.Black,
                                                        color = if (isVerified) Color(0xFF047857) else if (isSubmitted) Color(0xFF1D4ED8) else Color(0xFFBE123C),
                                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 3.dp)
                                                    )
                                                }
                                            }

                                            if (!req.value.isNullOrEmpty()) {
                                                Surface(
                                                    shape = RoundedCornerShape(8.dp),
                                                    color = Color(0xFFF1F5F9),
                                                    modifier = Modifier.fillMaxWidth()
                                                ) {
                                                    Row(
                                                        modifier = Modifier.padding(8.dp),
                                                        horizontalArrangement = Arrangement.SpaceBetween,
                                                        verticalAlignment = Alignment.CenterVertically
                                                    ) {
                                                        Text("Submitted: ${req.value}", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF334155), modifier = Modifier.weight(1f))
                                                        if (req.value.startsWith("http") || req.value.startsWith("/uploads")) {
                                                            TextButton(
                                                                onClick = { openDocumentUrl(context, req.value) },
                                                                contentPadding = PaddingValues(horizontal = 6.dp, vertical = 2.dp)
                                                            ) {
                                                                Text("View Doc", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFF2563EB))
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                            Button(
                                                onClick = {
                                                    activeReq = req
                                                    detailText = req.value ?: ""
                                                    notesText = req.clientNotes ?: ""
                                                    showRequirementSheet = true
                                                },
                                                colors = ButtonDefaults.buttonColors(containerColor = if (isSubmitted) Color(0xFF0F172A) else Color(0xFFDC2626)),
                                                shape = RoundedCornerShape(8.dp),
                                                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                                            ) {
                                                Icon(Icons.Default.Edit, contentDescription = null, modifier = Modifier.size(14.dp))
                                                Spacer(modifier = Modifier.width(6.dp))
                                                Text(if (isSubmitted) "Update Submission" else "Fulfill Requirement", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Assigned Lead Expert Card
                item {
                    val expert = order.assignedEmployee
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Text("Assigned Compliance Advisor", fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                            if (expert != null) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Surface(shape = CircleShape, color = Color(0xFFFEF2F2), modifier = Modifier.size(40.dp)) {
                                        Box(contentAlignment = Alignment.Center) {
                                            Icon(Icons.Default.Person, contentDescription = null, tint = Color(0xFFDC2626))
                                        }
                                    }
                                    Spacer(modifier = Modifier.width(10.dp))
                                    Column {
                                        Text(expert.name.ifEmpty { "Compliance Lead" }, fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                        Text(expert.role.ifEmpty { "CA / Legal Advisor" }.uppercase(), fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                                    }
                                }
                            } else {
                                Text("Dedicated expert being assigned.", fontSize = 12.sp, color = Color(0xFF64748B))
                            }
                        }
                    }
                }
            }

            // --- SUB-TAB 2: VAULT & DELIVERABLES ---
            if (currentDetailTab == "documents") {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text("Government & Statutory Certificates", fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))

                            if (order.adminDocuments.isEmpty()) {
                                Text("Official certificates will appear here once issued.", fontSize = 12.sp, color = Color(0xFF94A3B8))
                            } else {
                                order.adminDocuments.forEach { doc ->
                                    Surface(
                                        shape = RoundedCornerShape(12.dp),
                                        color = Color(0xFFECFDF5),
                                        border = BorderStroke(1.dp, Color(0xFFA7F3D0)),
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Row(
                                            modifier = Modifier.padding(12.dp).fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Column(modifier = Modifier.weight(1f)) {
                                                Text(doc.name, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF064E3B))
                                                Text("Issued Certificate", fontSize = 10.sp, color = Color(0xFF047857))
                                            }
                                            Button(
                                                onClick = { openDocumentUrl(context, doc.url) },
                                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF047857)),
                                                shape = RoundedCornerShape(8.dp),
                                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                                            ) {
                                                Text("View Document", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text("Order Uploads & Attachments", fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                Text(
                                    "Open Full Vault ›",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Black,
                                    color = Color(0xFFDC2626),
                                    modifier = Modifier.clickable { onSelectTab("Vault") }
                                )
                            }

                            if (order.clientDocuments.isEmpty()) {
                                Text("No files attached to this order.", fontSize = 12.sp, color = Color(0xFF94A3B8))
                            } else {
                                order.clientDocuments.forEach { doc ->
                                    Surface(
                                        shape = RoundedCornerShape(12.dp),
                                        color = Color(0xFFF8FAFC),
                                        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Row(
                                            modifier = Modifier.padding(12.dp).fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Text(doc.name, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A), modifier = Modifier.weight(1f))
                                            OutlinedButton(
                                                onClick = { openDocumentUrl(context, doc.url) },
                                                shape = RoundedCornerShape(8.dp),
                                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                                            ) {
                                                Text("View File", fontSize = 10.sp)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // --- SUB-TAB 3: INVOICES & PAYMENTS ---
            if (currentDetailTab == "financials") {
                item {
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Card(
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Text("TOTAL FEE", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                                Text("₹${order.price.toInt()}", fontSize = 15.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                            }
                        }
                        Card(
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFFECFDF5)),
                            border = BorderStroke(1.dp, Color(0xFFA7F3D0))
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Text("PAID TO DATE", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF047857))
                                Text("₹${totalPaid.toInt()}", fontSize = 15.sp, fontWeight = FontWeight.Black, color = Color(0xFF064E3B))
                            }
                        }
                        Card(
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFFFEF2F2)),
                            border = BorderStroke(1.dp, Color(0xFFFECDD3))
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Text("OUTSTANDING", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFFBE123C))
                                Text("₹${balance.toInt()}", fontSize = 15.sp, fontWeight = FontWeight.Black, color = Color(0xFF991B1B))
                            }
                        }
                    }
                }

                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                                Text("Payment Transactions Log", fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                if (balance > 0) {
                                    Button(
                                        onClick = { showPaymentBottomSheet = true },
                                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                                        shape = RoundedCornerShape(8.dp),
                                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                                    ) {
                                        Text("Settle Balance", fontSize = 10.sp, fontWeight = FontWeight.Black)
                                    }
                                }
                            }

                            if (orderPayments.isEmpty()) {
                                Text("No recorded payments yet.", fontSize = 12.sp, color = Color(0xFF94A3B8))
                            } else {
                                orderPayments.forEach { p ->
                                    Surface(
                                        shape = RoundedCornerShape(12.dp),
                                        color = Color(0xFFF8FAFC),
                                        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Row(
                                            modifier = Modifier.padding(12.dp).fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Column {
                                                Text("₹${p.amount.toInt()}", fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                                Text("${if (p.createdAt.length >= 10) p.createdAt.substring(0, 10) else "Recent"} • ${p.method}", fontSize = 10.sp, color = Color(0xFF64748B))
                                            }
                                            Surface(
                                                color = if (p.status == "Completed" || p.status == "Paid") Color(0xFFD1FAE5) else Color(0xFFFEF3C7),
                                                shape = RoundedCornerShape(6.dp)
                                            ) {
                                                Text(
                                                    text = p.status.uppercase(),
                                                    fontSize = 9.sp,
                                                    fontWeight = FontWeight.Black,
                                                    color = if (p.status == "Completed" || p.status == "Paid") Color(0xFF047857) else Color(0xFFB45309),
                                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
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

            item {
                Spacer(modifier = Modifier.height(80.dp))
            }
        }
    }

    // --- REQUIREMENT FULFILLMENT MODAL BOTTOM SHEET (3 DOCUMENT OPTIONS INCLUDED) ---
    if (showRequirementSheet && activeReq != null) {
        ModalBottomSheet(
            onDismissRequest = { showRequirementSheet = false },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            containerColor = Color.White
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Text(
                    text = activeReq!!.title,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF0F172A)
                )
                Text(
                    text = activeReq!!.description.ifEmpty { "Please submit requested information or document below." },
                    fontSize = 12.sp,
                    color = Color(0xFF64748B)
                )

                if (isSubmittingReq) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        modifier = Modifier.padding(vertical = 12.dp)
                    ) {
                        CircularProgressIndicator(color = Color(0xFFDC2626), modifier = Modifier.size(24.dp))
                        Text("Submitting details...", fontSize = 13.sp, fontWeight = FontWeight.Bold)
                    }
                } else {
                    if (activeReq!!.type == "Detail") {
                        // Text detail submission form
                        OutlinedTextField(
                            value = detailText,
                            onValueChange = { detailText = it },
                            label = { Text("Your Input / Value") },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp)
                        )

                        OutlinedTextField(
                            value = notesText,
                            onValueChange = { notesText = it },
                            label = { Text("Notes for Expert / CA (Optional)") },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp)
                        )

                        Button(
                            onClick = {
                                submitRequirementPayload(
                                    mapOf(
                                        "value" to detailText,
                                        "notes" to notesText,
                                        "isSubmitted" to true,
                                        "status" to "Submitted"
                                    )
                                )
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth().height(48.dp)
                        ) {
                            Text("Submit Details for Verification", fontSize = 13.sp, fontWeight = FontWeight.Black)
                        }
                    } else {
                        // Document requirement: 3 UPLOAD OPTIONS
                        Text("Choose document submission method:", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF334155))

                        // Option 1: Standard Verification Documents (Vault)
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    showRequirementSheet = false
                                    showVaultSelectionSheet = true
                                },
                            shape = RoundedCornerShape(14.dp),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFFEFF6FF)),
                            border = BorderStroke(1.dp, Color(0xFFBFDBFE))
                        ) {
                            Row(
                                modifier = Modifier.padding(14.dp).fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                Surface(shape = CircleShape, color = Color(0xFFDBEAFE), modifier = Modifier.size(36.dp)) {
                                    Box(contentAlignment = Alignment.Center) {
                                        Icon(Icons.Default.VerifiedUser, contentDescription = null, tint = Color(0xFF1D4ED8), modifier = Modifier.size(18.dp))
                                    }
                                }
                                Column(modifier = Modifier.weight(1f)) {
                                    Text("Option 1: Standard Verification Vault", fontSize = 12.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E40AF))
                                    Text("Select from Aadhaar, PAN, GST, Cheque, Address Proof", fontSize = 10.sp, color = Color(0xFF2563EB))
                                }
                                Icon(Icons.Default.ChevronRight, contentDescription = null, tint = Color(0xFF1D4ED8))
                            }
                        }

                        // Option 2: Upload from Device Storage
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { reqFilePickerLauncher.launch("*/*") },
                            shape = RoundedCornerShape(14.dp),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFFF8FAFC)),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                        ) {
                            Row(
                                modifier = Modifier.padding(14.dp).fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                Surface(shape = CircleShape, color = Color(0xFFF1F5F9), modifier = Modifier.size(36.dp)) {
                                    Box(contentAlignment = Alignment.Center) {
                                        Icon(Icons.Default.Folder, contentDescription = null, tint = Color(0xFF475569), modifier = Modifier.size(18.dp))
                                    }
                                }
                                Column(modifier = Modifier.weight(1f)) {
                                    Text("Option 2: Upload from Phone Memory", fontSize = 12.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                    Text("Select PDF, PNG, JPG file from device storage", fontSize = 10.sp, color = Color(0xFF64748B))
                                }
                                Icon(Icons.Default.ChevronRight, contentDescription = null, tint = Color.Gray)
                            }
                        }

                        // Option 3: Click a Photo with Camera
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { reqCameraLauncher.launch() },
                            shape = RoundedCornerShape(14.dp),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFFFEF2F2)),
                            border = BorderStroke(1.dp, Color(0xFFFECDD3))
                        ) {
                            Row(
                                modifier = Modifier.padding(14.dp).fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                Surface(shape = CircleShape, color = Color(0xFFFFE4E6), modifier = Modifier.size(36.dp)) {
                                    Box(contentAlignment = Alignment.Center) {
                                        Icon(Icons.Default.PhotoCamera, contentDescription = null, tint = Color(0xFFDC2626), modifier = Modifier.size(18.dp))
                                    }
                                }
                                Column(modifier = Modifier.weight(1f)) {
                                    Text("Option 3: Click a Photo with Camera", fontSize = 12.sp, fontWeight = FontWeight.Black, color = Color(0xFF991B1B))
                                    Text("Take a fresh picture using phone camera", fontSize = 10.sp, color = Color(0xFFBE123C))
                                }
                                Icon(Icons.Default.ChevronRight, contentDescription = null, tint = Color(0xFFDC2626))
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))
            }
        }
    }

    // --- VAULT STANDARD DOCUMENT SELECTION SHEET ---
    if (showVaultSelectionSheet && activeReq != null) {
        ModalBottomSheet(
            onDismissRequest = { showVaultSelectionSheet = false },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            containerColor = Color.White
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Text(
                    text = "Select Vault Standard Document",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF0F172A)
                )
                Text(
                    text = "Attach an auto-verified standard document from your central vault:",
                    fontSize = 12.sp,
                    color = Color(0xFF64748B)
                )

                STANDARD_KYC_DOCS.forEach { docType ->
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                submitRequirementPayload(
                                    mapOf(
                                        "value" to docType.title,
                                        "docType" to docType.id,
                                        "fromVault" to true,
                                        "isSubmitted" to true,
                                        "status" to "Submitted"
                                    )
                                )
                            },
                        shape = RoundedCornerShape(14.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFF8FAFC)),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Row(
                            modifier = Modifier.padding(14.dp).fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Icon(docType.icon, contentDescription = null, tint = Color(0xFFDC2626), modifier = Modifier.size(20.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(docType.title, fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                Text(docType.description, fontSize = 10.sp, color = Color(0xFF64748B))
                            }
                            Icon(Icons.Default.Check, contentDescription = null, tint = Color(0xFF047857))
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))
            }
        }
    }

    // --- SUPPORT QUERY MODAL SHEET ---
    if (showSupportModal && selectedOrder != null) {
        ModalBottomSheet(
            onDismissRequest = { showSupportModal = false },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            containerColor = Color.White
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Text("Ask Support on Order #${selectedOrder.id.takeLast(8).uppercase()}", fontSize = 18.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                Text("Tag a question directly for your assigned compliance expert.", fontSize = 12.sp, color = Color(0xFF64748B))

                OutlinedTextField(
                    value = querySubject,
                    onValueChange = { querySubject = it },
                    label = { Text("Query Subject") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )

                OutlinedTextField(
                    value = queryDescription,
                    onValueChange = { queryDescription = it },
                    label = { Text("Detailed Description / Question") },
                    modifier = Modifier.fillMaxWidth().height(100.dp),
                    shape = RoundedCornerShape(12.dp)
                )

                Button(
                    onClick = {
                        if (querySubject.isBlank() || queryDescription.isBlank()) {
                            Toast.makeText(context, "Please fill in all fields", Toast.LENGTH_SHORT).show()
                            return@Button
                        }
                        isSubmittingTicket = true
                        scope.launch {
                            try {
                                val req = CreateTicketRequest(
                                    subject = "[${selectedOrder.serviceName}] $querySubject",
                                    description = queryDescription,
                                    priority = "Medium"
                                )
                                val res = api.createTicket(req)
                                if (res.isSuccessful) {
                                    Toast.makeText(context, "Support ticket submitted successfully!", Toast.LENGTH_SHORT).show()
                                    showSupportModal = false
                                    querySubject = ""
                                    queryDescription = ""
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
                    modifier = Modifier.fillMaxWidth().height(48.dp)
                ) {
                    if (isSubmittingTicket) {
                        CircularProgressIndicator(color = Color.White, modifier = Modifier.size(20.dp))
                    } else {
                        Text("Send Query to Support Team", fontSize = 13.sp, fontWeight = FontWeight.Black)
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))
            }
        }
    }

    // --- RAZORPAY PAYMENT BOTTOM SHEET INTEGRATION ---
    if (showPaymentBottomSheet && selectedOrder != null) {
        val orderPayments = viewModel.payments.filter { p -> p.order?.id == selectedOrder.id || p.serviceName.equals(selectedOrder.serviceName, ignoreCase = true) }
        val totalPaid = orderPayments.filter { it.status == "Completed" || it.status == "Paid" }.sumOf { it.amount }
        val balance = (selectedOrder.price - totalPaid).coerceAtLeast(0.0)
        CustomPaymentBottomSheet(
            key = "rzp_live_51P...",
            orderId = selectedOrder.id,
            amount = (balance * 100).toLong(),
            currency = "INR",
            serviceName = selectedOrder.serviceName,
            packageName = selectedOrder.packageName,
            customerName = (sessionManager.getUserName() ?: "").ifEmpty { "Customer" },
            customerEmail = (sessionManager.getUserEmail() ?: "").ifEmpty { "customer@vrhere.in" },
            customerPhone = "918008530606",
            onSuccess = { paymentId, orderId, signature ->
                showPaymentBottomSheet = false
                Toast.makeText(context, "Payment successful! ID: $paymentId", Toast.LENGTH_LONG).show()
                viewModel.refreshAllData(silent = true)
            },
            onFailure = { errorMsg ->
                Toast.makeText(context, "Payment failed: $errorMsg", Toast.LENGTH_LONG).show()
            },
            onClose = {
                showPaymentBottomSheet = false
            }
        )
    }
}
