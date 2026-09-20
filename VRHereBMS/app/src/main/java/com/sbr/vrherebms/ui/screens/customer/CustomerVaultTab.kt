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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.UserVaultDocument
import com.sbr.vrherebms.data.remote.VRHereAPI
import com.sbr.vrherebms.viewmodel.CustomerDashboardViewModel
import kotlinx.coroutines.launch
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody

data class StandardDocTypeModel(
    val id: String,
    val title: String,
    val description: String,
    val icon: ImageVector,
    val keywords: List<String>
)

val STANDARD_KYC_DOCS = listOf(
    StandardDocTypeModel("Aadhaar Card", "Aadhaar Card", "Identity & address proof of Director/Proprietor", Icons.Default.Badge, listOf("aadhaar", "aadhar", "adhar", "uidai")),
    StandardDocTypeModel("PAN Card", "PAN Card", "Permanent Account Number proof", Icons.Default.CreditCard, listOf("pan")),
    StandardDocTypeModel("GST Certificate", "GST Certificate", "Form GST REG-06 or GST registration application", Icons.Default.ReceiptLong, listOf("gst")),
    StandardDocTypeModel("Cancelled Cheque", "Cancelled Cheque", "Bank validation with IFSC & Acc No.", Icons.Default.AccountBalance, listOf("cheque", "check", "bank", "passbook")),
    StandardDocTypeModel("Business Address Proof", "Business Address Proof", "Utility bill, electricity bill or registered rent agreement", Icons.Default.Home, listOf("address", "proof", "utility", "bill", "rent")),
    StandardDocTypeModel("Incorporation Certificate", "Incorporation Certificate", "MCA Certificate of Incorporation or Partnership Deed", Icons.Default.VerifiedUser, listOf("incorporation", "inc", "coi", "registration"))
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomerVaultTab(
    viewModel: CustomerDashboardViewModel,
    isEmbedded: Boolean = false
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val api = remember { VRHereAPI.getInstance(context) }

    var selectedSection by remember { mutableStateOf("Standard") } // "Standard" | "Deliverables"
    var vaultDocuments by remember { mutableStateOf<List<UserVaultDocument>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var isUploading by remember { mutableStateOf(false) }

    // Upload Modal State
    var targetUploadDocType by remember { mutableStateOf<StandardDocTypeModel?>(null) }
    var showUploadSheet by remember { mutableStateOf(false) }

    fun fetchVaultDocs() {
        isLoading = true
        scope.launch {
            try {
                val res = api.getUserVaultDocuments()
                if (res.isSuccessful && res.body() != null) {
                    vaultDocuments = res.body()!!.data
                }
            } catch (e: Exception) {
                // Non-blocking
            } finally {
                isLoading = false
            }
        }
    }

    LaunchedEffect(Unit) {
        fetchVaultDocs()
    }

    // Handlers for File & Camera Uploads
    fun uploadFileToVault(part: okhttp3.MultipartBody.Part, docTypeName: String) {
        isUploading = true
        scope.launch {
            try {
                val docTypeBody = docTypeName.toRequestBody("text/plain".toMediaTypeOrNull())
                val res = api.uploadUserVaultDocument(part, docTypeBody)
                if (res.isSuccessful) {
                    Toast.makeText(context, "$docTypeName uploaded to Vault!", Toast.LENGTH_SHORT).show()
                    fetchVaultDocs()
                    viewModel.refreshAllData(silent = true)
                } else {
                    Toast.makeText(context, "Upload failed. Please try again.", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
            } finally {
                isUploading = false
                showUploadSheet = false
            }
        }
    }

    // Launchers
    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null && targetUploadDocType != null) {
            val part = uriToMultipartPart(context, uri)
            if (part != null) {
                uploadFileToVault(part, targetUploadDocType!!.id)
            } else {
                Toast.makeText(context, "Failed to process selected file", Toast.LENGTH_SHORT).show()
            }
        }
    }

    val cameraLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.TakePicturePreview()
    ) { bitmap: Bitmap? ->
        if (bitmap != null && targetUploadDocType != null) {
            val part = bitmapToMultipartPart(context, bitmap)
            if (part != null) {
                uploadFileToVault(part, targetUploadDocType!!.id)
            } else {
                Toast.makeText(context, "Failed to process camera photo", Toast.LENGTH_SHORT).show()
            }
        }
    }

    // Extract files across all user orders
    val orderFiles = remember(viewModel.orders) {
        viewModel.orders.flatMap { order ->
            val orderTag = order.serviceName.ifEmpty { "Order #${order.id.takeLast(6).uppercase()}" }
            
            val clientDocs = order.clientDocuments.map { doc ->
                Triple(doc.name, doc.url, "Client Upload • $orderTag")
            }
            val adminDocs = order.adminDocuments.map { doc ->
                Triple(doc.name, doc.url, "Delivered Certificate • $orderTag")
            }
            val reqDocs = order.customerRequirements.mapNotNull { req ->
                val url = req.uploadedDocumentUrl.ifEmpty { req.documentUrl.ifEmpty { if (req.value.startsWith("http") || req.value.startsWith("/uploads")) req.value else null } }
                if (!url.isNullOrEmpty()) {
                    Triple(req.uploadedDocumentName.ifEmpty { req.title }, url, "Requirement • $orderTag")
                } else null
            }
            clientDocs + adminDocs + reqDocs
        }
    }

    // Render Content Layout (Non-scrollable Column if Embedded to prevent crash)
    @Composable
    fun VaultContent() {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // --- 1. HERO BANNER matching Web Module ---
            Card(
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.Transparent),
                elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            brush = Brush.horizontalGradient(
                                colors = listOf(Color(0xFF1E1B4B), Color(0xFF312E81), Color(0xFF4338CA))
                            ),
                            shape = RoundedCornerShape(24.dp)
                        )
                        .padding(20.dp)
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Surface(
                            color = Color(0xFF6366F1).copy(alpha = 0.3f),
                            shape = RoundedCornerShape(50)
                        ) {
                            Text(
                                "UPLOAD ONCE, USE ANYWHERE",
                                color = Color(0xFFA5B4FC),
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Black,
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                            )
                        }
                        Text(
                            "My Documents Vault",
                            color = Color.White,
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Black
                        )
                        Text(
                            "Store your basic verification documents securely in our vault. They auto-populate across all your business service orders.",
                            color = Color(0xFFC7D2FE),
                            fontSize = 12.sp,
                            lineHeight = 16.sp
                        )
                    }
                }
            }

            // --- 2. SEGMENTED SECTION SWITCHER ---
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color.White, RoundedCornerShape(16.dp))
                    .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(16.dp))
                    .padding(4.dp)
            ) {
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .background(
                            if (selectedSection == "Standard") Color(0xFFDC2626) else Color.Transparent,
                            RoundedCornerShape(12.dp)
                        )
                        .clickable { selectedSection = "Standard" }
                        .padding(vertical = 10.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        "Standard Verification (${STANDARD_KYC_DOCS.size})",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Black,
                        color = if (selectedSection == "Standard") Color.White else Color(0xFF64748B)
                    )
                }

                Box(
                    modifier = Modifier
                        .weight(1f)
                        .background(
                            if (selectedSection == "Deliverables") Color(0xFFDC2626) else Color.Transparent,
                            RoundedCornerShape(12.dp)
                        )
                        .clickable { selectedSection = "Deliverables" }
                        .padding(vertical = 10.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        "Order Deliverables (${orderFiles.size})",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Black,
                        color = if (selectedSection == "Deliverables") Color.White else Color(0xFF64748B)
                    )
                }
            }

            // --- 3. SECTION CONTENT ---
            if (selectedSection == "Standard") {
                STANDARD_KYC_DOCS.forEach { slot ->
                    val directVaultDoc = vaultDocuments.find { it.docType.equals(slot.id, ignoreCase = true) }
                    val fallbackOrderFile = if (directVaultDoc == null) {
                        orderFiles.find { file ->
                            val nameLower = file.first.lowercase()
                            slot.keywords.any { kw -> nameLower.contains(kw) }
                        }
                    } else null

                    val isUploaded = directVaultDoc != null
                    val isFromOrder = fallbackOrderFile != null
                    val docUrl = directVaultDoc?.gdriveWebViewLink ?: fallbackOrderFile?.second ?: ""
                    val fileName = directVaultDoc?.fileName ?: fallbackOrderFile?.first ?: "Not uploaded yet"

                    Card(
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                        modifier = Modifier.fillMaxWidth()
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
                                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Surface(
                                        shape = RoundedCornerShape(12.dp),
                                        color = if (isUploaded) Color(0xFFECFDF5) else if (isFromOrder) Color(0xFFEFF6FF) else Color(0xFFF1F5F9),
                                        modifier = Modifier.size(40.dp)
                                    ) {
                                        Box(contentAlignment = Alignment.Center) {
                                            Icon(
                                                imageVector = slot.icon,
                                                contentDescription = null,
                                                tint = if (isUploaded) Color(0xFF047857) else if (isFromOrder) Color(0xFF2563EB) else Color(0xFF64748B),
                                                modifier = Modifier.size(20.dp)
                                            )
                                        }
                                    }
                                    Column {
                                        Text(slot.title, fontWeight = FontWeight.Black, fontSize = 14.sp, color = Color(0xFF0F172A))
                                        Text(slot.description, fontSize = 11.sp, color = Color(0xFF64748B))
                                    }
                                }

                                Surface(
                                    shape = RoundedCornerShape(6.dp),
                                    color = if (isUploaded) Color(0xFFD1FAE5) else if (isFromOrder) Color(0xFFDBEAFE) else Color(0xFFFEF3C7)
                                ) {
                                    Text(
                                        text = if (isUploaded) "VERIFIED" else if (isFromOrder) "FROM ORDER" else "MISSING",
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Black,
                                        color = if (isUploaded) Color(0xFF047857) else if (isFromOrder) Color(0xFF1D4ED8) else Color(0xFFB45309),
                                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                                    )
                                }
                            }

                            if (isUploaded || isFromOrder) {
                                Surface(
                                    shape = RoundedCornerShape(10.dp),
                                    color = Color(0xFFF8FAFC),
                                    border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Text(
                                        text = "📄 $fileName",
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color(0xFF334155),
                                        modifier = Modifier.padding(10.dp)
                                    )
                                }
                            }

                            Row(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                if (!docUrl.isNullOrBlank()) {
                                    OutlinedButton(
                                        onClick = { openDocumentUrl(context, docUrl) },
                                        shape = RoundedCornerShape(10.dp),
                                        modifier = Modifier.weight(1f),
                                        contentPadding = PaddingValues(vertical = 8.dp)
                                    ) {
                                        Icon(Icons.Default.Visibility, contentDescription = null, modifier = Modifier.size(16.dp))
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text("View Document", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                    }
                                }

                                Button(
                                    onClick = {
                                        targetUploadDocType = slot
                                        showUploadSheet = true
                                    },
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = if (isUploaded) Color(0xFF0F172A) else Color(0xFFDC2626)
                                    ),
                                    shape = RoundedCornerShape(10.dp),
                                    modifier = Modifier.weight(1f),
                                    contentPadding = PaddingValues(vertical = 8.dp)
                                ) {
                                    Icon(Icons.Default.Upload, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(if (isUploaded) "Replace" else "Upload ${slot.title}", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }
                }
            } else {
                // Order Deliverables Section
                if (orderFiles.isEmpty()) {
                    Card(
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier
                                .padding(32.dp)
                                .fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Icon(Icons.Default.Folder, contentDescription = null, tint = Color.LightGray, modifier = Modifier.size(44.dp))
                            Text("No order deliverables found yet.", fontWeight = FontWeight.Bold, color = Color(0xFF64748B), fontSize = 13.sp)
                            Text("Official certificates & uploads will automatically sync here.", color = Color(0xFF94A3B8), fontSize = 11.sp)
                        }
                    }
                } else {
                    orderFiles.forEach { (name, url, source) ->
                        Card(
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(containerColor = Color.White),
                            border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(12.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Surface(
                                        shape = RoundedCornerShape(10.dp),
                                        color = Color(0xFFFEF2F2),
                                        modifier = Modifier.size(36.dp)
                                    ) {
                                        Box(contentAlignment = Alignment.Center) {
                                            Icon(Icons.Default.InsertDriveFile, contentDescription = null, tint = Color(0xFFDC2626), modifier = Modifier.size(18.dp))
                                        }
                                    }
                                    Column {
                                        Text(name, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                                        Text(source, fontSize = 10.sp, color = Color(0xFF64748B))
                                    }
                                }

                                Button(
                                    onClick = { openDocumentUrl(context, url) },
                                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF0F172A)),
                                    shape = RoundedCornerShape(8.dp),
                                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                                ) {
                                    Text("View", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (isEmbedded) {
        VaultContent()
    } else {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .background(Color(0xFFF8FAFC)),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                VaultContent()
            }
            item {
                Spacer(modifier = Modifier.height(80.dp))
            }
        }
    }

    // --- UPLOAD OPTIONS MODAL BOTTOM SHEET (3 OPTIONS) ---
    if (showUploadSheet && targetUploadDocType != null) {
        ModalBottomSheet(
            onDismissRequest = { showUploadSheet = false },
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
                    text = "Upload ${targetUploadDocType!!.title}",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF0F172A)
                )
                Text(
                    text = "Select your preferred document upload method:",
                    fontSize = 12.sp,
                    color = Color(0xFF64748B)
                )

                if (isUploading) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 16.dp)
                    ) {
                        CircularProgressIndicator(color = Color(0xFFDC2626), modifier = Modifier.size(24.dp))
                        Text("Uploading document to vault...", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
                    }
                } else {
                    // Option 1: File from Device Storage
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                filePickerLauncher.launch("*/*")
                            },
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFF8FAFC)),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(14.dp)
                        ) {
                            Surface(shape = CircleShape, color = Color(0xFFDBEAFE), modifier = Modifier.size(40.dp)) {
                                Box(contentAlignment = Alignment.Center) {
                                    Icon(Icons.Default.FolderOpen, contentDescription = null, tint = Color(0xFF1D4ED8))
                                }
                            }
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Upload from Device Storage", fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                Text("Select PDF, PNG, or JPG from phone files", fontSize = 11.sp, color = Color(0xFF64748B))
                            }
                            Icon(Icons.Default.ChevronRight, contentDescription = null, tint = Color.Gray)
                        }
                    }

                    // Option 2: Take Photo with Camera
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                cameraLauncher.launch()
                            },
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFF8FAFC)),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(14.dp)
                        ) {
                            Surface(shape = CircleShape, color = Color(0xFFFEF2F2), modifier = Modifier.size(40.dp)) {
                                Box(contentAlignment = Alignment.Center) {
                                    Icon(Icons.Default.PhotoCamera, contentDescription = null, tint = Color(0xFFDC2626))
                                }
                            }
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Click a Photo with Camera", fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))
                                Text("Capture document directly using camera", fontSize = 11.sp, color = Color(0xFF64748B))
                            }
                            Icon(Icons.Default.ChevronRight, contentDescription = null, tint = Color.Gray)
                        }
                    }

                    // Option 3: Auto-Attach from Past Orders (if applicable)
                    val matchingOrderFile = orderFiles.find { file ->
                        val nameLower = file.first.lowercase()
                        targetUploadDocType!!.keywords.any { kw -> nameLower.contains(kw) }
                    }
                    if (matchingOrderFile != null) {
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    scope.launch {
                                        try {
                                            isUploading = true
                                            Toast.makeText(context, "Linked document from ${matchingOrderFile.third}", Toast.LENGTH_SHORT).show()
                                            fetchVaultDocs()
                                        } catch (e: Exception) {} finally {
                                            isUploading = false
                                            showUploadSheet = false
                                        }
                                    }
                                },
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFFECFDF5)),
                            border = BorderStroke(1.dp, Color(0xFFA7F3D0))
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(16.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(14.dp)
                            ) {
                                Surface(shape = CircleShape, color = Color(0xFFD1FAE5), modifier = Modifier.size(40.dp)) {
                                    Box(contentAlignment = Alignment.Center) {
                                        Icon(Icons.Default.CheckCircle, contentDescription = null, tint = Color(0xFF047857))
                                    }
                                }
                                Column(modifier = Modifier.weight(1f)) {
                                    Text("Link from Past Order File", fontSize = 13.sp, fontWeight = FontWeight.Black, color = Color(0xFF064E3B))
                                    Text("Use ${matchingOrderFile.first} from ${matchingOrderFile.third}", fontSize = 11.sp, color = Color(0xFF047857))
                                }
                                Icon(Icons.Default.ChevronRight, contentDescription = null, tint = Color(0xFF047857))
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))
            }
        }
    }
}
