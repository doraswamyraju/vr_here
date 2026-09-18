package com.sbr.vrherebms.ui.screens.customer

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
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

data class MasterKYCSlotModel(
    val id: String,
    val title: String,
    val desc: String,
    val icon: ImageVector
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomerVaultTab(viewModel: CustomerDashboardViewModel) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val api = remember { VRHereAPI.getInstance(context) }

    var selectedTab by remember { mutableStateOf("Master KYC") }
    var vaultDocuments by remember { mutableStateOf<List<UserVaultDocument>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }

    val kycSlots = listOf(
        MasterKYCSlotModel("PAN Card", "PAN Card (Director/Company)", "Permanent Account Number proof", Icons.Default.CreditCard),
        MasterKYCSlotModel("Aadhaar Card", "Aadhaar Card (Director)", "Identity & address verification", Icons.Default.Badge),
        MasterKYCSlotModel("GST Certificate", "GST Registration Certificate", "Form GST REG-06 or application", Icons.Default.ReceiptLong),
        MasterKYCSlotModel("Cancelled Cheque", "Cancelled Cheque / Bank Proof", "Bank validation with IFSC & Acc No.", Icons.Default.AccountBalance),
        MasterKYCSlotModel("Business Address Proof", "Business Address Proof", "Utility bill or registered rent agreement", Icons.Default.Home),
        MasterKYCSlotModel("Incorporation Certificate", "Certificate of Incorporation", "MCA COI or Partnership Deed", Icons.Default.VerifiedUser),
        MasterKYCSlotModel("MSME / Udyam Certificate", "MSME / Udyam Registration", "Government MSME recognition certificate", Icons.Default.Star),
        MasterKYCSlotModel("MOA & AOA", "MOA & AOA / Partnership Deed", "Charter documents and bylaws", Icons.Default.FolderZip)
    )

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

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFFF8FAFC)),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Header
        item {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    "Document Vault & Master KYC",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF0F172A)
                )
                Text(
                    "Centralized secure repository for business identity proofs & certificates.",
                    fontSize = 12.sp,
                    color = Color.Gray
                )
            }
        }

        // Segmented Tab Picker
        item {
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = Color.White
            ) {
                TabRow(
                    selectedTabIndex = if (selectedTab == "Master KYC") 0 else 1,
                    containerColor = Color.Transparent,
                    contentColor = Color(0xFF6366F1),
                    divider = {}
                ) {
                    Tab(
                        selected = selectedTab == "Master KYC",
                        onClick = { selectedTab = "Master KYC" },
                        text = { Text("Master KYC (8)", fontWeight = FontWeight.Bold, fontSize = 12.sp) }
                    )
                    Tab(
                        selected = selectedTab == "Deliverables",
                        onClick = { selectedTab = "Deliverables" },
                        text = { Text("Order Deliverables", fontWeight = FontWeight.Bold, fontSize = 12.sp) }
                    )
                }
            }
        }

        if (selectedTab == "Master KYC") {
            // 8 Master KYC Slots
            items(kycSlots) { slot ->
                val existingDoc = vaultDocuments.find { it.docType.equals(slot.id, ignoreCase = true) }
                val isUploaded = existingDoc != null

                Card(
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.Top,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Surface(
                                shape = RoundedCornerShape(10.dp),
                                color = if (isUploaded) Color(0xFFECFDF5) else Color(0xFFF1F5F9),
                                modifier = Modifier.size(40.dp)
                            ) {
                                Box(contentAlignment = Alignment.Center) {
                                    Icon(
                                        imageVector = slot.icon,
                                        contentDescription = null,
                                        tint = if (isUploaded) Color(0xFF10B981) else Color(0xFF64748B),
                                        modifier = Modifier.size(20.dp)
                                    )
                                }
                            }

                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = slot.title,
                                    fontWeight = FontWeight.Black,
                                    fontSize = 13.sp,
                                    color = Color(0xFF0F172A)
                                )
                                Text(
                                    text = slot.desc,
                                    fontSize = 11.sp,
                                    color = Color.Gray
                                )
                            }

                            Surface(
                                shape = RoundedCornerShape(6.dp),
                                color = if (isUploaded) Color(0xFFD1FAE5) else Color(0xFFFEF3C7)
                            ) {
                                Text(
                                    text = if (isUploaded) "VERIFIED" else "REQUIRED",
                                    color = if (isUploaded) Color(0xFF065F46) else Color(0xFF92400E),
                                    fontWeight = FontWeight.Black,
                                    fontSize = 9.sp,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 3.dp)
                                )
                            }
                        }

                        if (existingDoc != null) {
                            Surface(
                                shape = RoundedCornerShape(8.dp),
                                color = Color(0xFFF8FAFC),
                                border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Row(
                                    modifier = Modifier.padding(8.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = "• ${existingDoc.fileName}",
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color(0xFF334155),
                                        modifier = Modifier.weight(1f)
                                    )

                                    if (!existingDoc.gdriveWebViewLink.isNullOrEmpty()) {
                                        TextButton(
                                            onClick = {
                                                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(existingDoc.gdriveWebViewLink))
                                                context.startActivity(intent)
                                            },
                                            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)
                                        ) {
                                            Text("View", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF2563EB))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // Order Deliverables Explorer
            val allOrderDocs = viewModel.orders.flatMap { order ->
                order.clientDocuments.map { Pair(it, "Upload • ${order.serviceName}") } +
                order.adminDocuments.map { Pair(it, "Certificate • ${order.serviceName}") }
            }

            if (allOrderDocs.isEmpty()) {
                item {
                    Card(
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(32.dp).fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Icon(Icons.Default.Folder, contentDescription = null, tint = Color.LightGray, modifier = Modifier.size(40.dp))
                            Text("No order deliverables found yet", fontWeight = FontWeight.Bold, color = Color.Gray, fontSize = 13.sp)
                        }
                    }
                }
            } else {
                items(allOrderDocs) { (doc, source) ->
                    Card(
                        shape = RoundedCornerShape(14.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp).fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.InsertDriveFile,
                                contentDescription = null,
                                tint = Color(0xFFDC2626),
                                modifier = Modifier.size(24.dp)
                            )

                            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text(
                                    text = doc.name,
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFF0F172A),
                                    maxLines = 1
                                )
                                Text(
                                    text = source,
                                    fontSize = 10.sp,
                                    color = Color.Gray,
                                    maxLines = 1
                                )
                            }

                            IconButton(onClick = {
                                if (doc.url.isNotEmpty()) {
                                    val fullUrl = if (doc.url.startsWith("http")) doc.url else "https://vrhere.in/${doc.url.trimStart('/')}"
                                    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(fullUrl))
                                    context.startActivity(intent)
                                }
                            }) {
                                Icon(
                                    imageVector = Icons.Default.Download,
                                    contentDescription = "Download",
                                    tint = Color(0xFF6366F1),
                                    modifier = Modifier.size(20.dp)
                                )
                            }
                        }
                    }
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(100.dp))
        }
    }
}
