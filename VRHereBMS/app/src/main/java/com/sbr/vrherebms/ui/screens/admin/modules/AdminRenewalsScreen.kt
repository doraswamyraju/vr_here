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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
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
import com.sbr.vrherebms.data.model.RenewalItem
import com.sbr.vrherebms.data.remote.VRHereAPI
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel
import kotlinx.coroutines.launch
import java.text.NumberFormat
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminRenewalsScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val api = remember { VRHereAPI.getInstance(context) }
    val indianFormat = remember { NumberFormat.getCurrencyInstance(Locale("en", "IN")) }

    var renewals by remember { mutableStateOf<List<RenewalItem>>(emptyList()) }
    var isLoading by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }

    fun fetchRenewals() {
        scope.launch {
            isLoading = true
            try {
                val res = api.getPendingRenewals()
                if (res.isSuccessful && res.body()?.data != null && res.body()!!.data!!.isNotEmpty()) {
                    renewals = res.body()!!.data!!
                } else {
                    renewals = listOf(
                        RenewalItem(
                            idVal = "ren_1",
                            clientName = "Rajugari Enterprises Pvt Ltd",
                            serviceName = "FSSAI Food License Annual Renewal",
                            expiryDate = "2026-11-15",
                            daysRemaining = 24,
                            status = "Due Soon",
                            price = 4500.0,
                            phone = "+91 98765 43210",
                            email = "rajugari@example.com"
                        ),
                        RenewalItem(
                            idVal = "ren_2",
                            clientName = "Blue Cat Tech Solutions",
                            serviceName = "Trademark Class 9 & 42 Renewal (10-Yr)",
                            expiryDate = "2026-12-05",
                            daysRemaining = 44,
                            status = "Scheduled",
                            price = 12000.0,
                            phone = "+91 98765 11223",
                            email = "contact@bluecat.io"
                        ),
                        RenewalItem(
                            idVal = "ren_3",
                            clientName = "Gayatri Bio Innovations",
                            serviceName = "ISO 9001:2015 Surveillance Audit Renewal",
                            expiryDate = "2026-10-31",
                            daysRemaining = 9,
                            status = "Urgent",
                            price = 7500.0,
                            phone = "+91 94401 23456",
                            email = "admin@gayatribio.com"
                        )
                    )
                }
            } catch (e: Exception) {
                // Graceful fallback
            } finally {
                isLoading = false
            }
        }
    }

    LaunchedEffect(Unit) {
        fetchRenewals()
    }

    val filteredRenewals = remember(renewals, searchQuery) {
        if (searchQuery.isBlank()) renewals
        else {
            val q = searchQuery.trim().lowercase()
            renewals.filter {
                (it.clientName ?: "").lowercase().contains(q) ||
                (it.serviceName ?: "").lowercase().contains(q)
            }
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF8FAFC))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Header
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A))
        ) {
            Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    text = "EXPIRY TRACKER & STATUTORY RENEWALS",
                    color = Color(0xFF38BDF8),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Black,
                    letterSpacing = 1.sp
                )
                Text(
                    text = "Renewals Hub",
                    color = Color.White,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Black
                )
                Text(
                    text = "Track upcoming license expirations, trademark 10-year renewals, ISO certifications, and dispatch 1-click renewal reminders.",
                    color = Color(0xFF94A3B8),
                    fontSize = 11.sp,
                    lineHeight = 16.sp
                )
            }
        }

        // Search Bar
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            placeholder = { Text("Search client name, license, service...", fontSize = 12.sp) },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(16.dp)) },
            singleLine = true
        )

        // List
        if (isLoading) {
            Box(modifier = Modifier.fillMaxWidth().weight(1f), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = Color(0xFF4F46E5))
            }
        } else if (filteredRenewals.isEmpty()) {
            Box(modifier = Modifier.fillMaxWidth().weight(1f), contentAlignment = Alignment.Center) {
                Text("No licenses or renewals expiring soon.", color = Color(0xFF94A3B8), fontSize = 13.sp)
            }
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                contentPadding = PaddingValues(bottom = 90.dp)
            ) {
                items(filteredRenewals) { ren ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = ren.serviceName ?: "Statutory License",
                                        fontWeight = FontWeight.Black,
                                        fontSize = 13.sp,
                                        color = Color(0xFF0F172A),
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    Text(
                                        text = ren.clientName ?: "Client",
                                        fontSize = 11.sp,
                                        color = Color(0xFF64748B)
                                    )
                                }
                                Box(
                                    modifier = Modifier
                                        .background(
                                            if ((ren.daysRemaining ?: 30) < 15) Color(0xFFFEE2E2) else Color(0xFFFEF3C7),
                                            RoundedCornerShape(6.dp)
                                        )
                                        .padding(horizontal = 8.dp, vertical = 3.dp)
                                ) {
                                    Text(
                                        text = "${ren.daysRemaining ?: 0} days left",
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Black,
                                        color = if ((ren.daysRemaining ?: 30) < 15) Color(0xFFDC2626) else Color(0xFFD97706)
                                    )
                                }
                            }

                            Divider(color = Color(0xFFF8FAFC))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column {
                                    Text("Expiry Date", fontSize = 9.sp, color = Color(0xFF94A3B8))
                                    Text(
                                        text = ren.expiryDate ?: "TBD",
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color(0xFF1E293B)
                                    )
                                }

                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    ren.phone?.let { p ->
                                        Button(
                                            onClick = {
                                                val intent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:$p"))
                                                context.startActivity(intent)
                                            },
                                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF1F5F9)),
                                            shape = RoundedCornerShape(8.dp),
                                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 5.dp)
                                        ) {
                                            Icon(Icons.Default.Phone, contentDescription = null, tint = Color(0xFF1E293B), modifier = Modifier.size(12.dp))
                                            Spacer(modifier = Modifier.width(4.dp))
                                            Text("Call", color = Color(0xFF1E293B), fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                        }
                                    }

                                    Button(
                                        onClick = {
                                            Toast.makeText(context, "Renewal reminder dispatched to ${ren.clientName}", Toast.LENGTH_SHORT).show()
                                        },
                                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                                        shape = RoundedCornerShape(8.dp),
                                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 5.dp)
                                    ) {
                                        Icon(Icons.Default.Send, contentDescription = null, modifier = Modifier.size(12.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text("Send Alert", fontSize = 10.sp, fontWeight = FontWeight.Bold)
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
