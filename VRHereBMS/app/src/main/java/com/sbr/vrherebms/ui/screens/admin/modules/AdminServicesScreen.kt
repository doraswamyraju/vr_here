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
import androidx.compose.foundation.rememberScrollState
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.sbr.vrherebms.data.model.InteractiveCapsuleItem
import com.sbr.vrherebms.data.model.MobileServiceDetail
import com.sbr.vrherebms.data.model.ServicesHeaderConfigRequest
import com.sbr.vrherebms.data.remote.VRHereAPI
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminServicesScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val api = remember { VRHereAPI.getInstance(context) }

    var selectedSubTab by remember { mutableStateOf("Global Header Settings") }

    // Global Header Settings State
    var showTicker by remember { mutableStateOf(true) }
    var tickerMessage by remember { mutableStateOf("⚡ Limited Time: Flat 20% OFF on all Private Limited Company Registrations this week!") }
    var tickerGradient by remember { mutableStateOf("from-indigo-600 to-purple-600") }
    var isSavingHeader by remember { mutableStateOf(false) }

    var capsulesList by remember {
        mutableStateOf(
            listOf(
                InteractiveCapsuleItem("1", "⚡ Fast-Track Incorporation", "#EFF6FF", "#2563EB", "⚡"),
                InteractiveCapsuleItem("2", "🛡️ Trademark & IP Shield", "#FDF4FF", "#C026D3", "🛡️"),
                InteractiveCapsuleItem("3", "📊 Valuation & Pitch Deck", "#ECFDF5", "#059669", "📊"),
                InteractiveCapsuleItem("4", "⚖️ Legal & Tech Contracts", "#FFFBEB", "#D97706", "⚖️")
            )
        )
    }

    var showAddCapsuleDialog by remember { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF8FAFC))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Subtab Switcher
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFFE2E8F0), RoundedCornerShape(12.dp))
                .padding(4.dp)
        ) {
            listOf("Global Header Settings", "Landing Pages & SEO / AEO Hub").forEach { tab ->
                val isSelected = selectedSubTab == tab
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .background(if (isSelected) Color.White else Color.Transparent, RoundedCornerShape(10.dp))
                        .clickable { selectedSubTab = tab }
                        .padding(vertical = 8.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = tab,
                        fontSize = 11.sp,
                        fontWeight = if (isSelected) FontWeight.Black else FontWeight.Bold,
                        color = if (isSelected) Color(0xFF4F46E5) else Color(0xFF64748B)
                    )
                }
            }
        }

        if (selectedSubTab == "Global Header Settings") {
            // Subtab 1 Content
            Column(
                modifier = Modifier
                    .weight(1f)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Ticker Card
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("GLOBAL ANNOUNCEMENT TICKER", fontSize = 11.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                            Switch(checked = showTicker, onCheckedChange = { showTicker = it })
                        }

                        OutlinedTextField(
                            value = tickerMessage,
                            onValueChange = { tickerMessage = it },
                            label = { Text("Ticker Headline Text") },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(10.dp)
                        )

                        Button(
                            onClick = {
                                isSavingHeader = true
                                scope.launch {
                                    try {
                                        val req = ServicesHeaderConfigRequest(
                                            showTicker = showTicker,
                                            tickerMessage = tickerMessage,
                                            tickerGradient = tickerGradient,
                                            capsules = capsulesList
                                        )
                                        val res = api.saveServicesHeaderConfig(req)
                                        if (res.isSuccessful) {
                                            Toast.makeText(context, "Header settings saved & deployed!", Toast.LENGTH_SHORT).show()
                                        }
                                    } catch (e: Exception) {
                                        Toast.makeText(context, "Saved locally", Toast.LENGTH_SHORT).show()
                                    }
                                    isSavingHeader = false
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Save & Deploy Header Config", fontWeight = FontWeight.Bold)
                        }
                    }
                }

                // Interactive Physics Capsules Card
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                ) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("INTERACTIVE CAPSULES & KEYWORDS", fontSize = 11.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
                            IconButton(onClick = { showAddCapsuleDialog = true }) {
                                Icon(Icons.Default.AddCircle, contentDescription = null, tint = Color(0xFF4F46E5))
                            }
                        }

                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            capsulesList.forEach { cap ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .background(Color(0xFFF8FAFC), RoundedCornerShape(10.dp))
                                        .padding(horizontal = 12.dp, vertical = 8.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                        Text(cap.icon, fontSize = 14.sp)
                                        Text(cap.text, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                                    }
                                    IconButton(
                                        onClick = { capsulesList = capsulesList.filter { it.id != cap.id } },
                                        modifier = Modifier.size(24.dp)
                                    ) {
                                        Icon(Icons.Default.Delete, contentDescription = null, tint = Color(0xFFEF4444), modifier = Modifier.size(14.dp))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // Subtab 2: Landing Pages & SEO / AEO Hub
            LandingPagesSeoHubView()
        }
    }

    if (showAddCapsuleDialog) {
        var capText by remember { mutableStateOf("") }
        var capIcon by remember { mutableStateOf("🚀") }

        AlertDialog(
            onDismissRequest = { showAddCapsuleDialog = false },
            title = { Text("Add Interactive Capsule", fontWeight = FontWeight.Black) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedTextField(value = capIcon, onValueChange = { capIcon = it }, label = { Text("Icon / Emoji") }, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = capText, onValueChange = { capText = it }, label = { Text("Capsule Title") }, modifier = Modifier.fillMaxWidth())
                }
            },
            confirmButton = {
                Button(onClick = {
                    if (capText.isNotEmpty()) {
                        capsulesList = capsulesList + InteractiveCapsuleItem(
                            id = System.currentTimeMillis().toString(),
                            text = capText,
                            icon = capIcon
                        )
                        showAddCapsuleDialog = false
                    }
                }) {
                    Text("Add Capsule")
                }
            },
            dismissButton = {
                TextButton(onClick = { showAddCapsuleDialog = false }) { Text("Cancel") }
            }
        )
    }
}

@Composable
private fun LandingPagesSeoHubView() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("LANDING PAGES & AI-AEO ENGINE", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))

        listOf(
            "Company Registration in India" to "Rank #1 • 8 FAQs • 3 Packages",
            "GST Registration & Monthly Filing" to "Rank #2 • 6 FAQs • 2 Packages",
            "Trademark & Copyright Protection" to "Rank #1 • 10 FAQs • 4 Packages",
            "Startup Valuation & 409A Reports" to "Rank #3 • 5 FAQs • 3 Packages"
        ).forEach { (title, sub) ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(14.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(title, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                        Text(sub, fontSize = 11.sp, color = Color(0xFF64748B))
                    }
                    IconButton(onClick = { }) {
                        Icon(Icons.Default.Edit, contentDescription = null, tint = Color(0xFF4F46E5), modifier = Modifier.size(18.dp))
                    }
                }
            }
        }
    }
}
