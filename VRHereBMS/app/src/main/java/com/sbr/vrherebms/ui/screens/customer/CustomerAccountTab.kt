package com.sbr.vrherebms.ui.screens.customer

import android.graphics.Bitmap
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.result.launch
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
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
import com.sbr.vrherebms.data.local.SessionManager
import com.sbr.vrherebms.data.model.OrderResponse
import com.sbr.vrherebms.data.remote.VRHereAPI
import com.sbr.vrherebms.ui.components.VRAvatarView
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel
import kotlinx.coroutines.launch
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomerAccountTab(
    viewModel: CustomerDashboardViewModel,
    onSelectTab: (String) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val api = remember { VRHereAPI.getInstance(context) }
    val sessionManager = remember { SessionManager(context) }

    // Screen State: Sub-Tab Selection ('profile' | 'vault' | 'renewals' | 'billing')
    var activeSubTab by remember { mutableStateOf("profile") }

    // User Profile & Form State
    var userNameInput by remember { mutableStateOf(sessionManager.getUserName() ?: "") }
    var userEmailInput by remember { mutableStateOf(sessionManager.getUserEmail() ?: "") }
    var userPhoneInput by remember { mutableStateOf(sessionManager.getPhone()) }
    var companyNameInput by remember { mutableStateOf(sessionManager.getCompanyName() ?: "") }
    var businessTypeInput by remember { mutableStateOf("Private Limited") }
    var gstinInput by remember { mutableStateOf("") }
    var panNumberInput by remember { mutableStateOf("") }
    var addressInput by remember { mutableStateOf("") }

    var profilePhotoUrl by remember { mutableStateOf(sessionManager.getProfilePhoto()) }
    var companyLogoUrl by remember { mutableStateOf(sessionManager.getCompanyLogo()) }

    var isSavingProfile by remember { mutableStateOf(false) }
    var isUploadingPhoto by remember { mutableStateOf(false) }
    var isUploadingLogo by remember { mutableStateOf(false) }

    // Renewal Checkout Sheet State
    var selectedRenewalOrder by remember { mutableStateOf<OrderResponse?>(null) }
    var showRenewalCheckoutSheet by remember { mutableStateOf(false) }

    val payments = viewModel.payments
    val orders = viewModel.orders
    val totalSpent = remember(payments) { payments.sumOf { it.amount } }

    // Image Upload Handlers
    fun uploadAvatarFile(part: okhttp3.MultipartBody.Part) {
        isUploadingPhoto = true
        scope.launch {
            try {
                val res = api.uploadAvatar(part)
                if (res.isSuccessful && res.body() != null) {
                    val url = res.body()!!["url"] ?: ""
                    profilePhotoUrl = url
                    sessionManager.saveProfilePhoto(url)
                    viewModel.refreshAllData(silent = true)
                    Toast.makeText(context, "Profile photo updated!", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(context, "Photo upload failed", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
            } finally {
                isUploadingPhoto = false
            }
        }
    }

    fun uploadLogoFile(part: okhttp3.MultipartBody.Part) {
        isUploadingLogo = true
        scope.launch {
            try {
                val res = api.uploadCompanyLogo(part)
                if (res.isSuccessful && res.body() != null) {
                    val url = res.body()!!["url"] ?: ""
                    companyLogoUrl = url
                    sessionManager.saveCompanyLogo(url)
                    viewModel.refreshAllData(silent = true)
                    Toast.makeText(context, "Company logo updated!", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(context, "Logo upload failed", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
            } finally {
                isUploadingLogo = false
            }
        }
    }

    // Launchers
    val photoPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null) {
            val part = uriToMultipartPart(context, uri, paramName = "image")
            if (part != null) uploadAvatarFile(part)
        }
    }

    val photoCameraLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.TakePicturePreview()
    ) { bitmap: Bitmap? ->
        if (bitmap != null) {
            val part = bitmapToMultipartPart(context, bitmap, paramName = "image")
            if (part != null) uploadAvatarFile(part)
        }
    }

    val logoPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null) {
            val part = uriToMultipartPart(context, uri, paramName = "image")
            if (part != null) uploadLogoFile(part)
        }
    }

    // Save Profile Form Handler
    fun saveProfileChanges() {
        if (userNameInput.isBlank() || userEmailInput.isBlank()) {
            Toast.makeText(context, "Name and Email are required", Toast.LENGTH_SHORT).show()
            return
        }
        isSavingProfile = true
        scope.launch {
            try {
                val body = mapOf(
                    "name" to userNameInput,
                    "email" to userEmailInput,
                    "phone" to userPhoneInput,
                    "companyName" to companyNameInput,
                    "businessType" to businessTypeInput,
                    "gstin" to gstinInput,
                    "panNumber" to panNumberInput,
                    "address" to addressInput
                )
                val res = api.updateProfile(body)
                if (res.isSuccessful) {
                    sessionManager.saveCompanyName(companyNameInput)
                    sessionManager.savePhone(userPhoneInput)
                    viewModel.refreshAllData(silent = true)
                    Toast.makeText(context, "Profile & Business Info updated successfully!", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(context, "Failed to update profile", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
            } finally {
                isSavingProfile = false
            }
        }
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFFF8FAFC)),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // --- 1. HERO ACCOUNT HEADER CARD ---
        item {
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
                                listOf(Color(0xFF0F172A), Color(0xFF1E1B4B), Color(0xFF312E81))
                            ),
                            shape = RoundedCornerShape(24.dp)
                        )
                        .padding(20.dp)
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(14.dp)
                        ) {
                            Box(contentAlignment = Alignment.BottomEnd) {
                                VRAvatarView(
                                    photoUrl = profilePhotoUrl ?: viewModel.profilePhoto,
                                    name = userNameInput.ifEmpty { "Client" },
                                    size = 56.dp,
                                    borderWidth = 2.dp,
                                    borderColor = Color(0xFF818CF8),
                                    fontSize = 20.sp
                                )
                                Surface(
                                    shape = CircleShape,
                                    color = Color(0xFFDC2626),
                                    modifier = Modifier
                                        .size(20.dp)
                                        .clickable { photoPickerLauncher.launch("image/*") }
                                ) {
                                    Box(contentAlignment = Alignment.Center) {
                                        Icon(Icons.Default.CameraAlt, contentDescription = null, tint = Color.White, modifier = Modifier.size(12.dp))
                                    }
                                }
                            }

                            Column(modifier = Modifier.weight(1f)) {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                    Text(
                                        text = userNameInput.ifEmpty { "Customer Account" },
                                        fontSize = 18.sp,
                                        fontWeight = FontWeight.Black,
                                        color = Color.White,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    Surface(shape = RoundedCornerShape(50), color = Color(0xFF10B981).copy(alpha = 0.2f)) {
                                        Text("VERIFIED", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF34D399), modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                                    }
                                }
                                Text(
                                    text = "$userEmailInput ${if (userPhoneInput.isNotEmpty()) "• $userPhoneInput" else ""}",
                                    fontSize = 11.sp,
                                    color = Color(0xFFC7D2FE),
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                if (companyNameInput.isNotEmpty()) {
                                    Text(
                                        text = companyNameInput,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color(0xFFF43F5E)
                                    )
                                }
                            }
                        }

                        // Quick Stats Pill Row
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(Color.White.copy(alpha = 0.08f), RoundedCornerShape(14.dp))
                                .padding(12.dp),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column {
                                Text("TOTAL INVESTMENT", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                                Text("₹${String.format("%,.0f", totalSpent)}", fontSize = 15.sp, fontWeight = FontWeight.Black, color = Color(0xFF34D399))
                            }
                            Column(horizontalAlignment = Alignment.End) {
                                Text("ACTIVE ORDERS", fontSize = 8.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                                Text("${orders.size}", fontSize = 15.sp, fontWeight = FontWeight.Black, color = Color.White)
                            }
                        }
                    }
                }
            }
        }

        // --- 2. SUB-TABS NAVIGATION BAR ---
        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color.White, RoundedCornerShape(16.dp))
                    .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(16.dp))
                    .padding(4.dp),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                val subTabs = listOf(
                    "profile" to "Profile",
                    "vault" to "Vault",
                    "renewals" to "Renewals",
                    "billing" to "Billing"
                )
                subTabs.forEach { (key, label) ->
                    val isSel = activeSubTab == key
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .background(
                                if (isSel) Color(0xFFDC2626) else Color.Transparent,
                                RoundedCornerShape(12.dp)
                            )
                            .clickable { activeSubTab = key }
                            .padding(vertical = 10.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            label,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Black,
                            color = if (isSel) Color.White else Color(0xFF64748B)
                        )
                    }
                }
            }
        }

        // --- 3. SUB-TAB CONTENT ---
        when (activeSubTab) {
            "profile" -> {
                // VISUAL BRANDING UPLOADER CARDS
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                            Text("Profile Photo & Business Logo", fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                            Text("Personalize your profile and upload official company logo for GST invoices & filings.", fontSize = 11.sp, color = Color(0xFF64748B))

                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                // Personal Photo Upload Card
                                Card(
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(14.dp),
                                    colors = CardDefaults.cardColors(containerColor = Color(0xFFF8FAFC)),
                                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                                ) {
                                    Column(
                                        modifier = Modifier.padding(12.dp).fillMaxWidth(),
                                        horizontalAlignment = Alignment.CenterHorizontally,
                                        verticalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        VRAvatarView(photoUrl = profilePhotoUrl, name = userNameInput, size = 44.dp)
                                        Text("Personal Photo", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                        if (isUploadingPhoto) {
                                            CircularProgressIndicator(color = Color(0xFFDC2626), modifier = Modifier.size(20.dp))
                                        } else {
                                            Button(
                                                onClick = { photoPickerLauncher.launch("image/*") },
                                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF0F172A)),
                                                shape = RoundedCornerShape(8.dp),
                                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                                            ) {
                                                Text(if (profilePhotoUrl.isNullOrEmpty()) "Upload" else "Change", fontSize = 10.sp)
                                            }
                                        }
                                    }
                                }

                                // Company Logo Upload Card
                                Card(
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(14.dp),
                                    colors = CardDefaults.cardColors(containerColor = Color(0xFFF8FAFC)),
                                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                                ) {
                                    Column(
                                        modifier = Modifier.padding(12.dp).fillMaxWidth(),
                                        horizontalAlignment = Alignment.CenterHorizontally,
                                        verticalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        VRAvatarView(photoUrl = companyLogoUrl, name = companyNameInput.ifEmpty { "Company" }, size = 44.dp)
                                        Text("Company Logo", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                        if (isUploadingLogo) {
                                            CircularProgressIndicator(color = Color(0xFFDC2626), modifier = Modifier.size(20.dp))
                                        } else {
                                            Button(
                                                onClick = { logoPickerLauncher.launch("image/*") },
                                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF0F172A)),
                                                shape = RoundedCornerShape(8.dp),
                                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                                            ) {
                                                Text(if (companyLogoUrl.isNullOrEmpty()) "Upload" else "Change", fontSize = 10.sp)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // EDITABLE PROFILE & BUSINESS FORM
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text("Business & Contact Information", fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))

                            OutlinedTextField(
                                value = userNameInput,
                                onValueChange = { userNameInput = it },
                                label = { Text("Full Name / Primary Contact") },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp),
                                singleLine = true
                            )

                            OutlinedTextField(
                                value = userEmailInput,
                                onValueChange = { userEmailInput = it },
                                label = { Text("Email Address") },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp),
                                singleLine = true
                            )

                            OutlinedTextField(
                                value = userPhoneInput,
                                onValueChange = { userPhoneInput = it },
                                label = { Text("Phone Number") },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp),
                                singleLine = true
                            )

                            OutlinedTextField(
                                value = companyNameInput,
                                onValueChange = { companyNameInput = it },
                                label = { Text("Company / Business Name") },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp),
                                singleLine = true
                            )

                            // Entity Type Selector
                            Text("Business Entity Type:", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF334155))
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .horizontalScroll(rememberScrollState()),
                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                val types = listOf("Proprietorship", "Private Limited", "LLP", "Partnership Firm", "One Person Company", "Individual")
                                types.forEach { type ->
                                    val isSel = businessTypeInput == type
                                    Surface(
                                        shape = RoundedCornerShape(8.dp),
                                        color = if (isSel) Color(0xFF0F172A) else Color(0xFFF1F5F9),
                                        modifier = Modifier.clickable { businessTypeInput = type }
                                    ) {
                                        Text(type, fontSize = 10.sp, fontWeight = FontWeight.Bold, color = if (isSel) Color.White else Color(0xFF475569), modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp))
                                    }
                                }
                            }

                            OutlinedTextField(
                                value = gstinInput,
                                onValueChange = { gstinInput = it },
                                label = { Text("GSTIN (Optional)") },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp),
                                singleLine = true
                            )

                            OutlinedTextField(
                                value = panNumberInput,
                                onValueChange = { panNumberInput = it },
                                label = { Text("PAN Number (Optional)") },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp),
                                singleLine = true
                            )

                            OutlinedTextField(
                                value = addressInput,
                                onValueChange = { addressInput = it },
                                label = { Text("Registered Business Address") },
                                modifier = Modifier.fillMaxWidth().height(80.dp),
                                shape = RoundedCornerShape(12.dp)
                            )

                            Button(
                                onClick = { saveProfileChanges() },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier.fillMaxWidth().height(48.dp)
                            ) {
                                if (isSavingProfile) {
                                    CircularProgressIndicator(color = Color.White, modifier = Modifier.size(20.dp))
                                } else {
                                    Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Save Profile & Business Changes", fontSize = 12.sp, fontWeight = FontWeight.Black)
                                }
                            }
                        }
                    }
                }
            }

            "vault" -> {
                // EMBEDDED GOOGLE DRIVE DOCUMENT VAULT
                item {
                    CustomerVaultTab(viewModel = viewModel, isEmbedded = true)
                }
            }

            "renewals" -> {
                // RENEWALS & SUBSCRIPTIONS
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text("Active Registrations & Renewal Cycles", fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                            Text("Track annual compliance due dates, licenses & renewal invoices.", fontSize = 11.sp, color = Color(0xFF64748B))

                            if (orders.isEmpty()) {
                                Text("No active renewal cycles set up yet.", fontSize = 12.sp, color = Color(0xFF94A3B8))
                            } else {
                                orders.forEach { order ->
                                    Surface(
                                        shape = RoundedCornerShape(14.dp),
                                        color = Color(0xFFF8FAFC),
                                        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Row(
                                            modifier = Modifier.padding(12.dp).fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Column(modifier = Modifier.weight(1f)) {
                                                Text(order.serviceName, fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                                Text("Yearly Cycle • Status: ${order.status}", fontSize = 10.sp, color = Color(0xFF64748B))
                                            }
                                            Column(horizontalAlignment = Alignment.End) {
                                                Text("₹${order.price.toInt()}", fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                                Button(
                                                    onClick = {
                                                        selectedRenewalOrder = order
                                                        showRenewalCheckoutSheet = true
                                                    },
                                                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF047857)),
                                                    shape = RoundedCornerShape(8.dp),
                                                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)
                                                ) {
                                                    Text("Pay Renewal", fontSize = 9.sp, fontWeight = FontWeight.Bold)
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

            "billing" -> {
                // EMBEDDED BILLING & INVOICES HISTORY
                item {
                    CustomerInvoicesTab(viewModel = viewModel, isEmbedded = true)
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(80.dp))
        }
    }

    // --- RENEWAL PAYMENT CHECKOUT SHEET INTEGRATION ---
    if (showRenewalCheckoutSheet && selectedRenewalOrder != null) {
        val o = selectedRenewalOrder!!
        CustomPaymentBottomSheet(
            key = "rzp_live_51P...",
            orderId = o.id,
            amount = (o.price * 100).toLong(),
            currency = "INR",
            serviceName = "Renewal: ${o.serviceName}",
            packageName = o.packageName.ifEmpty { "Yearly Renewal" },
            customerName = (sessionManager.getUserName() ?: "").ifEmpty { "Customer" },
            customerEmail = (sessionManager.getUserEmail() ?: "").ifEmpty { "customer@vrhere.in" },
            customerPhone = "918008530606",
            onSuccess = { paymentId, orderId, signature ->
                showRenewalCheckoutSheet = false
                Toast.makeText(context, "Renewal payment successful!", Toast.LENGTH_LONG).show()
                viewModel.refreshAllData(silent = true)
            },
            onFailure = { err ->
                Toast.makeText(context, "Payment error: $err", Toast.LENGTH_LONG).show()
            },
            onClose = { showRenewalCheckoutSheet = false }
        )
    }
}
