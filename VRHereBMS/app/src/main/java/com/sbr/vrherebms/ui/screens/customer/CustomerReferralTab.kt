package com.sbr.vrherebms.ui.screens.customer

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.background
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.AddReferralLeadRequest
import com.sbr.vrherebms.data.model.CustomerReferralItem
import com.sbr.vrherebms.data.model.CustomerReferralStatsResponse
import com.sbr.vrherebms.data.model.UpiPayoutRequest
import com.sbr.vrherebms.data.remote.VRHereAPI
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomerReferralTab(
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val api = remember { VRHereAPI.getInstance(context) }

    var stats by remember { mutableStateOf<CustomerReferralStatsResponse?>(null) }
    var isLoading by remember { mutableStateOf(true) }
    var isCopied by remember { mutableStateOf(false) }

    // Modal Sheets
    var showAddLeadSheet by remember { mutableStateOf(false) }
    var showPayoutSheet by remember { mutableStateOf(false) }

    // Add Lead Form State
    var leadName by remember { mutableStateOf("") }
    var leadPhone by remember { mutableStateOf("") }
    var leadEmail by remember { mutableStateOf("") }
    var leadService by remember { mutableStateOf("Private Limited Company Registration") }
    var isSubmittingLead by remember { mutableStateOf(false) }

    // UPI Payout Form State
    var upiId by remember { mutableStateOf("") }
    var payoutAmount by remember { mutableStateOf("") }
    var isSubmittingPayout by remember { mutableStateOf(false) }

    val serviceOptions = listOf(
        "Private Limited Company Registration",
        "GST Registration & Filings",
        "LLP Registration",
        "Trademark Registration",
        "Income Tax Return & Assessment",
        "Bookkeeping & AaaS Package",
        "FSSAI Food License",
        "Import Export Code (IEC)",
        "ISO Certification"
    )

    fun fetchStats() {
        isLoading = true
        scope.launch {
            try {
                val res = api.getCustomerReferralStats()
                if (res.isSuccessful && res.body() != null) {
                    stats = res.body()
                    if (!res.body()!!.savedUpiId.isNullOrEmpty()) {
                        upiId = res.body()!!.savedUpiId!!
                    }
                }
            } catch (e: Exception) {
                Toast.makeText(context, "Error loading referrals: ${e.message}", Toast.LENGTH_SHORT).show()
            } finally {
                isLoading = false
            }
        }
    }

    LaunchedEffect(Unit) {
        fetchStats()
    }

    fun copyToClipboard(text: String) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("Referral Link", text)
        clipboard.setPrimaryClip(clip)
        isCopied = true
        Toast.makeText(context, "Referral link copied to clipboard!", Toast.LENGTH_SHORT).show()
    }

    fun shareOnWhatsApp() {
        val code = stats?.referralCode ?: ""
        val link = stats?.referralLink ?: ""
        val message = "Hey! I use VR Here for company registrations, GST, and CA compliances. You can get your business registered or file taxes with their expert CA team.\n\nUse my referral link for priority onboarding: $link (or code: $code)"
        val sendIntent = Intent(Intent.ACTION_VIEW).apply {
            data = Uri.parse("https://api.whatsapp.com/send?text=${Uri.encode(message)}")
        }
        try {
            context.startActivity(sendIntent)
        } catch (e: Exception) {
            val shareIntent = Intent().apply {
                action = Intent.ACTION_SEND
                putExtra(Intent.EXTRA_TEXT, message)
                type = "text/plain"
            }
            context.startActivity(Intent.createChooser(shareIntent, "Share referral via"))
        }
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF8FAFC)),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Hero Gradient Banner
        item {
            Card(
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.Transparent),
                elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            Brush.linearGradient(
                                colors = listOf(Color(0xFF991B1B), Color(0xFFDC2626), Color(0xFFEA580C))
                            )
                        )
                        .padding(20.dp)
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Surface(
                                shape = RoundedCornerShape(8.dp),
                                color = Color.Black.copy(alpha = 0.3f)
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Star,
                                        contentDescription = null,
                                        tint = Color(0xFFFBBF24),
                                        modifier = Modifier.size(14.dp)
                                    )
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text(
                                        text = "REFER & EARN CASH",
                                        color = Color(0xFFFBBF24),
                                        fontWeight = FontWeight.Black,
                                        fontSize = 10.sp
                                    )
                                }
                            }

                            Surface(
                                shape = RoundedCornerShape(12.dp),
                                color = Color.White.copy(alpha = 0.2f)
                            ) {
                                Text(
                                    text = "₹500 / Referral",
                                    color = Color.White,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 11.sp,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                                )
                            }
                        }

                        Text(
                            text = "Earn ₹500 for every business friend who incorporates or files taxes with us",
                            color = Color.White,
                            fontWeight = FontWeight.Bold,
                            fontSize = 17.sp,
                            lineHeight = 22.sp
                        )

                        // Code Box & Actions
                        Surface(
                            shape = RoundedCornerShape(16.dp),
                            color = Color.Black.copy(alpha = 0.25f),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(
                                modifier = Modifier.padding(14.dp),
                                verticalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column {
                                        Text(
                                            text = "YOUR EXCLUSIVE CODE",
                                            color = Color.White.copy(alpha = 0.8f),
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.Black
                                        )
                                        Text(
                                            text = stats?.referralCode ?: "VR-CLIENT",
                                            color = Color.White,
                                            fontSize = 18.sp,
                                            fontWeight = FontWeight.Black,
                                            fontFamily = FontFamily.Monospace
                                        )
                                    }

                                    Button(
                                        onClick = { copyToClipboard(stats?.referralLink ?: "") },
                                        colors = ButtonDefaults.buttonColors(containerColor = Color.White),
                                        shape = RoundedCornerShape(10.dp),
                                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.Share,
                                            contentDescription = null,
                                            tint = Color(0xFF991B1B),
                                            modifier = Modifier.size(14.dp)
                                        )
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text(
                                            text = if (isCopied) "COPIED" else "COPY LINK",
                                            color = Color(0xFF991B1B),
                                            fontWeight = FontWeight.Black,
                                            fontSize = 11.sp
                                        )
                                    }
                                }

                                Button(
                                    onClick = { shareOnWhatsApp() },
                                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF16A34A)),
                                    shape = RoundedCornerShape(10.dp),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Send,
                                        contentDescription = null,
                                        tint = Color.White,
                                        modifier = Modifier.size(16.dp)
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        text = "Share on WhatsApp Instantly",
                                        color = Color.White,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 13.sp
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        // 4 Key Stats Grid
        item {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    ReferralStatBox(
                        title = "TOTAL INVITED",
                        value = "${stats?.totalInvited ?: 0}",
                        icon = Icons.Default.Person,
                        tint = Color(0xFF2563EB),
                        modifier = Modifier.weight(1f)
                    )
                    ReferralStatBox(
                        title = "CONVERTED",
                        value = "${stats?.successfulConversions ?: 0}",
                        icon = Icons.Default.CheckCircle,
                        tint = Color(0xFF16A34A),
                        modifier = Modifier.weight(1f)
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    ReferralStatBox(
                        title = "TOTAL EARNED",
                        value = "₹${(stats?.totalEarned ?: 0.0).toInt()}",
                        icon = Icons.Default.Star,
                        tint = Color(0xFF9333EA),
                        modifier = Modifier.weight(1f)
                    )

                    // Wallet with Payout CTA
                    Card(
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
                        modifier = Modifier.weight(1f)
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    imageVector = Icons.Default.AccountBox,
                                    contentDescription = null,
                                    tint = Color(0xFFEA580C),
                                    modifier = Modifier.size(18.dp)
                                )
                                if ((stats?.walletBalance ?: 0.0) >= 500) {
                                    Surface(
                                        shape = RoundedCornerShape(6.dp),
                                        color = Color(0xFFEA580C),
                                        modifier = Modifier.clickable { showPayoutSheet = true }
                                    ) {
                                        Text(
                                            text = "PAYOUT",
                                            color = Color.White,
                                            fontWeight = FontWeight.Black,
                                            fontSize = 9.sp,
                                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                        )
                                    }
                                }
                            }
                            Text(
                                text = "WALLET",
                                color = Color.Gray,
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Black
                            )
                            Text(
                                text = "₹${(stats?.walletBalance ?: 0.0).toInt()}",
                                color = Color(0xFF0F172A),
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Black
                            )
                        }
                    }
                }
            }
        }

        // Direct Submit Lead CTA Button
        item {
            Button(
                onClick = { showAddLeadSheet = true },
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF0F172A)),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Add,
                    contentDescription = null,
                    tint = Color.White
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Refer a Friend Directly (Submit Contact)",
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp
                )
            }
        }

        // Activity List Header
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "REFERRAL ACTIVITY",
                    color = Color.Gray,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Black
                )
                IconButton(onClick = { fetchStats() }, modifier = Modifier.size(28.dp)) {
                    Icon(
                        imageVector = Icons.Default.Refresh,
                        contentDescription = "Refresh",
                        tint = Color(0xFFDC2626),
                        modifier = Modifier.size(16.dp)
                    )
                }
            }
        }

        // Activity List Items
        if (isLoading) {
            item {
                Box(modifier = Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = Color(0xFFDC2626))
                }
            }
        } else if (stats?.referrals.isNullOrEmpty()) {
            item {
                Card(
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(24.dp).fillMaxWidth(),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Star,
                            contentDescription = null,
                            tint = Color.Gray.copy(alpha = 0.5f),
                            modifier = Modifier.size(36.dp)
                        )
                        Text(
                            text = "No referrals yet",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = Color(0xFF475569)
                        )
                        Text(
                            text = "Share your referral link with business contacts to start earning ₹500 rewards.",
                            fontSize = 12.sp,
                            color = Color.Gray
                        )
                    }
                }
            }
        } else {
            items(stats!!.referrals) { item ->
                ReferralActivityRow(item)
            }
        }

        item {
            Spacer(modifier = Modifier.height(70.dp))
        }
    }

    // Modal Bottom Sheet: Add Lead Directly
    if (showAddLeadSheet) {
        ModalBottomSheet(
            onDismissRequest = { showAddLeadSheet = false }
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Text(
                    text = "Refer a Business Contact",
                    fontWeight = FontWeight.Black,
                    fontSize = 18.sp,
                    color = Color(0xFF0F172A)
                )

                OutlinedTextField(
                    value = leadName,
                    onValueChange = { leadName = it },
                    label = { Text("Contact Full Name") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )

                OutlinedTextField(
                    value = leadPhone,
                    onValueChange = { leadPhone = it },
                    label = { Text("10-Digit Mobile Number") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )

                OutlinedTextField(
                    value = leadEmail,
                    onValueChange = { leadEmail = it },
                    label = { Text("Email Address (Optional)") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )

                // Service Picker
                Text(
                    text = "Interested Service",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.Gray
                )
                var expandedDropdown by remember { mutableStateOf(false) }
                Box {
                    OutlinedButton(
                        onClick = { expandedDropdown = true },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text(text = leadService, modifier = Modifier.weight(1f))
                        Icon(imageVector = Icons.Default.ArrowDropDown, contentDescription = null)
                    }
                    DropdownMenu(
                        expanded = expandedDropdown,
                        onDismissRequest = { expandedDropdown = false }
                    ) {
                        serviceOptions.forEach { opt ->
                            DropdownMenuItem(
                                text = { Text(opt) },
                                onClick = {
                                    leadService = opt
                                    expandedDropdown = false
                                }
                            )
                        }
                    }
                }

                Button(
                    onClick = {
                        if (leadName.isBlank() || leadPhone.length < 10) {
                            Toast.makeText(context, "Please enter valid contact details", Toast.LENGTH_SHORT).show()
                            return@Button
                        }
                        isSubmittingLead = true
                        scope.launch {
                            try {
                                val res = api.addCustomerReferralLead(
                                    AddReferralLeadRequest(
                                        name = leadName.trim(),
                                        phone = leadPhone.trim(),
                                        email = leadEmail.ifBlank { null },
                                        interestedService = leadService
                                    )
                                )
                                if (res.isSuccessful) {
                                    Toast.makeText(context, "Referral submitted successfully!", Toast.LENGTH_LONG).show()
                                    showAddLeadSheet = false
                                    leadName = ""
                                    leadPhone = ""
                                    leadEmail = ""
                                    fetchStats()
                                } else {
                                    Toast.makeText(context, "Failed: ${res.message()}", Toast.LENGTH_SHORT).show()
                                }
                            } catch (e: Exception) {
                                Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
                            } finally {
                                isSubmittingLead = false
                            }
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    enabled = !isSubmittingLead
                ) {
                    if (isSubmittingLead) {
                        CircularProgressIndicator(color = Color.White, modifier = Modifier.size(20.dp))
                    } else {
                        Text("Submit Referral & Track", fontWeight = FontWeight.Bold)
                    }
                }

                Spacer(modifier = Modifier.height(20.dp))
            }
        }
    }

    // Modal Bottom Sheet: Request UPI Payout
    if (showPayoutSheet) {
        ModalBottomSheet(
            onDismissRequest = { showPayoutSheet = false }
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Text(
                    text = "Request UPI Payout",
                    fontWeight = FontWeight.Black,
                    fontSize = 18.sp,
                    color = Color(0xFF0F172A)
                )

                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = Color(0xFFF1F5F9),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text("Available for Withdrawal", fontSize = 13.sp, color = Color.Gray)
                        Text("₹${(stats?.walletBalance ?: 0.0).toInt()}", fontWeight = FontWeight.Black, color = Color(0xFF16A34A))
                    }
                }

                OutlinedTextField(
                    value = upiId,
                    onValueChange = { upiId = it },
                    label = { Text("UPI ID (e.g. mobile@upi)") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )

                OutlinedTextField(
                    value = payoutAmount,
                    onValueChange = { payoutAmount = it },
                    label = { Text("Withdrawal Amount (Min ₹500)") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )

                Button(
                    onClick = {
                        val amt = payoutAmount.toDoubleOrNull() ?: (stats?.walletBalance ?: 0.0)
                        if (!upiId.contains("@") || amt < 500) {
                            Toast.makeText(context, "Valid UPI ID & min ₹500 required", Toast.LENGTH_SHORT).show()
                            return@Button
                        }
                        isSubmittingPayout = true
                        scope.launch {
                            try {
                                val res = api.requestCustomerUpiPayout(UpiPayoutRequest(amount = amt, upiId = upiId.trim()))
                                if (res.isSuccessful) {
                                    Toast.makeText(context, "UPI Payout requested successfully!", Toast.LENGTH_LONG).show()
                                    showPayoutSheet = false
                                    payoutAmount = ""
                                    fetchStats()
                                } else {
                                    Toast.makeText(context, "Failed: ${res.message()}", Toast.LENGTH_SHORT).show()
                                }
                            } catch (e: Exception) {
                                Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
                            } finally {
                                isSubmittingPayout = false
                            }
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF16A34A)),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    enabled = !isSubmittingPayout
                ) {
                    if (isSubmittingPayout) {
                        CircularProgressIndicator(color = Color.White, modifier = Modifier.size(20.dp))
                    } else {
                        Text("Request Payout Transfer", fontWeight = FontWeight.Bold)
                    }
                }

                Spacer(modifier = Modifier.height(20.dp))
            }
        }
    }
}

// Color helper
private fun Color.Companion.opacity(alpha: Float): Color = Color(0f, 0f, 0f, alpha)

@Composable
private fun ReferralStatBox(
    title: String,
    value: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    tint: Color,
    modifier: Modifier = Modifier
) {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
        modifier = modifier
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = tint,
                modifier = Modifier.size(18.dp)
            )
            Text(
                text = title,
                color = Color.Gray,
                fontSize = 9.sp,
                fontWeight = FontWeight.Black
            )
            Text(
                text = value,
                color = Color(0xFF0F172A),
                fontSize = 18.sp,
                fontWeight = FontWeight.Black
            )
        }
    }
}

@Composable
private fun ReferralActivityRow(item: CustomerReferralItem) {
    val statusColor = when (item.status.lowercase()) {
        "rewarded", "converted" -> Color(0xFF16A34A)
        "order_placed" -> Color(0xFF2563EB)
        "registered" -> Color(0xFFEA580C)
        else -> Color.Gray
    }

    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .padding(12.dp)
                .fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(38.dp)
                    .clip(CircleShape)
                    .background(statusColor.copy(alpha = 0.12f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = if (item.status.lowercase() == "rewarded") Icons.Default.CheckCircle else Icons.Default.Person,
                    contentDescription = null,
                    tint = statusColor,
                    modifier = Modifier.size(20.dp)
                )
            }

            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    text = item.refereeName,
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    color = Color(0xFF0F172A)
                )
                Text(
                    text = item.interestedService ?: "Compliance & Registration",
                    fontSize = 11.sp,
                    color = Color.Gray,
                    maxLines = 1
                )
            }

            Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = statusColor.copy(alpha = 0.12f)
                ) {
                    Text(
                        text = item.status.uppercase(),
                        color = statusColor,
                        fontWeight = FontWeight.Black,
                        fontSize = 9.sp,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
                if (item.status.lowercase() == "rewarded") {
                    Text(
                        text = "+₹${(item.rewardAmount ?: 500.0).toInt()}",
                        color = Color(0xFF16A34A),
                        fontWeight = FontWeight.Black,
                        fontSize = 11.sp
                    )
                }
            }
        }
    }
}
