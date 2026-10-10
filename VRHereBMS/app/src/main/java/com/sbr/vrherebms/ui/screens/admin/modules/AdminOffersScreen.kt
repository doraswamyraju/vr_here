package com.sbr.vrherebms.ui.screens.admin.modules

import android.widget.Toast
import androidx.compose.animation.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.sbr.vrherebms.data.model.OfferItem
import com.sbr.vrherebms.data.remote.VRHereAPI
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel
import kotlinx.coroutines.launch
import java.text.NumberFormat
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminOffersScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val api = remember { VRHereAPI.getInstance(context) }
    val indianFormat = remember { NumberFormat.getCurrencyInstance(Locale("en", "IN")) }

    var offers by remember { mutableStateOf<List<OfferItem>>(emptyList()) }
    var isLoading by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }
    var showCreateDialog by remember { mutableStateOf(false) }

    fun fetchOffers() {
        scope.launch {
            isLoading = true
            try {
                val res = api.getAdminOffers()
                if (res.isSuccessful && res.body() != null) {
                    offers = res.body()!!
                } else {
                    offers = listOf(
                        OfferItem(
                            idVal = "off_1",
                            title = "ROC CCFS-2026 Amnesty Scheme",
                            subtitle = "100% Late Filing Penalty Waiver for pending MCA returns. Clear years of default with zero additional fees.",
                            badgeTag = "LIMITED PERIOD",
                            badgeColor = "#F43F5E",
                            discountAmount = 10000.0,
                            originalPrice = 15000.0,
                            discountedPrice = 5000.0,
                            eligibilityText = "Valid for active and defaulting Private Limited / OPC companies.",
                            ctaText = "Avail Scheme →",
                            isActive = true
                        ),
                        OfferItem(
                            idVal = "off_2",
                            title = "Startup India & 80-IAC 3-Year Exemption",
                            subtitle = "Get 100% Income Tax Exemption for 3 consecutive years with DPIIT Recognition & IMB Certification.",
                            badgeTag = "DPIIT EXCLUSIVE",
                            badgeColor = "#6366F1",
                            discountAmount = 5000.0,
                            originalPrice = 24999.0,
                            discountedPrice = 19999.0,
                            eligibilityText = "Incorporated within 10 years with turnover under ₹100 Crore.",
                            ctaText = "Claim Exemption →",
                            isActive = true
                        )
                    )
                }
            } catch (e: Exception) {
                // Fallback
            } finally {
                isLoading = false
            }
        }
    }

    LaunchedEffect(Unit) {
        fetchOffers()
    }

    val filteredOffers = remember(offers, searchQuery) {
        if (searchQuery.isBlank()) offers
        else {
            val q = searchQuery.trim().lowercase()
            offers.filter {
                it.title.lowercase().contains(q) || (it.subtitle ?: "").lowercase().contains(q)
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
        // Command Header
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A))
        ) {
            Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    text = "PROMOTIONS & STATUTORY SCHEMES",
                    color = Color(0xFF38BDF8),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Black,
                    letterSpacing = 1.sp
                )
                Text(
                    text = "Offers & Schemes",
                    color = Color.White,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Black
                )
                Text(
                    text = "Manage flash festival schemes, MCA amnesty waivers, and corporate service promotional banners across app and web portals.",
                    color = Color(0xFF94A3B8),
                    fontSize = 11.sp,
                    lineHeight = 16.sp
                )
            }
        }

        // Action Row
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(14.dp),
                placeholder = { Text("Search active schemes...", fontSize = 12.sp) },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(16.dp)) },
                singleLine = true
            )

            Button(
                onClick = { showCreateDialog = true },
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                shape = RoundedCornerShape(14.dp),
                contentPadding = PaddingValues(horizontal = 14.dp, vertical = 14.dp)
            ) {
                Icon(Icons.Default.Add, contentDescription = "Add", modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(4.dp))
                Text("New Scheme", fontSize = 11.sp, fontWeight = FontWeight.Bold)
            }
        }

        // Offers List
        if (isLoading) {
            Box(modifier = Modifier.fillMaxWidth().weight(1f), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = Color(0xFF4F46E5))
            }
        } else if (filteredOffers.isEmpty()) {
            Box(modifier = Modifier.fillMaxWidth().weight(1f), contentAlignment = Alignment.Center) {
                Text("No promotional schemes found.", color = Color(0xFF94A3B8), fontSize = 13.sp)
            }
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                contentPadding = PaddingValues(bottom = 90.dp)
            ) {
                items(filteredOffers) { off ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(18.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Box(
                                    modifier = Modifier
                                        .background(Color(0xFFFEE2E2), RoundedCornerShape(6.dp))
                                        .padding(horizontal = 8.dp, vertical = 3.dp)
                                ) {
                                    Text(
                                        text = off.badgeTag ?: "LIMITED TIME",
                                        color = Color(0xFFDC2626),
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Black
                                    )
                                }

                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                    Box(
                                        modifier = Modifier
                                            .background(if (off.isActive) Color(0xFFDCFCE7) else Color(0xFFF1F5F9), RoundedCornerShape(6.dp))
                                            .padding(horizontal = 6.dp, vertical = 2.dp)
                                    ) {
                                        Text(
                                            text = if (off.isActive) "LIVE" else "PAUSED",
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = if (off.isActive) Color(0xFF16A34A) else Color(0xFF64748B)
                                        )
                                    }
                                    IconButton(
                                        onClick = {
                                            scope.launch {
                                                try { api.deleteOffer(off.idVal) } catch (_: Exception) {}
                                                offers = offers.filter { it.idVal != off.idVal }
                                                Toast.makeText(context, "Scheme deleted", Toast.LENGTH_SHORT).show()
                                            }
                                        },
                                        modifier = Modifier.size(28.dp)
                                    ) {
                                        Icon(Icons.Default.DeleteOutline, contentDescription = "Delete", tint = Color(0xFFEF4444), modifier = Modifier.size(16.dp))
                                    }
                                }
                            }

                            Text(
                                text = off.title,
                                fontSize = 15.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFF0F172A)
                            )

                            off.subtitle?.let {
                                Text(
                                    text = it,
                                    fontSize = 11.sp,
                                    color = Color(0xFF64748B),
                                    lineHeight = 16.sp
                                )
                            }

                            Divider(color = Color(0xFFF8FAFC))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Text(
                                        text = indianFormat.format(off.discountedPrice ?: 0.0),
                                        fontSize = 16.sp,
                                        fontWeight = FontWeight.Black,
                                        color = Color(0xFF059669)
                                    )
                                    if ((off.originalPrice ?: 0.0) > 0) {
                                        Text(
                                            text = indianFormat.format(off.originalPrice ?: 0.0),
                                            fontSize = 12.sp,
                                            color = Color(0xFF94A3B8),
                                            textDecoration = TextDecoration.LineThrough
                                        )
                                    }
                                }

                                Text(
                                    text = off.ctaText ?: "Avail Scheme →",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFF4F46E5)
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    // Add Offer Dialog
    if (showCreateDialog) {
        var title by remember { mutableStateOf("") }
        var subtitle by remember { mutableStateOf("") }
        var originalPriceStr by remember { mutableStateOf("15000") }
        var discPriceStr by remember { mutableStateOf("9999") }

        Dialog(onDismissRequest = { showCreateDialog = false }) {
            Card(
                modifier = Modifier.fillMaxWidth().padding(8.dp),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp).verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text("Create Promotional Scheme", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))

                    OutlinedTextField(
                        value = title,
                        onValueChange = { title = it },
                        label = { Text("Scheme Name") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp)
                    )

                    OutlinedTextField(
                        value = subtitle,
                        onValueChange = { subtitle = it },
                        label = { Text("Scheme Benefits / Subtitle") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp),
                        minLines = 2
                    )

                    OutlinedTextField(
                        value = originalPriceStr,
                        onValueChange = { originalPriceStr = it },
                        label = { Text("Original Price (INR)") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                    )

                    OutlinedTextField(
                        value = discPriceStr,
                        onValueChange = { discPriceStr = it },
                        label = { Text("Promotional Price (INR)") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                    )

                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                        TextButton(onClick = { showCreateDialog = false }) {
                            Text("Cancel", color = Color(0xFF64748B))
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Button(
                            onClick = {
                                if (title.isBlank()) return@Button
                                val orig = originalPriceStr.toDoubleOrNull() ?: 0.0
                                val disc = discPriceStr.toDoubleOrNull() ?: 0.0
                                val newOff = OfferItem(
                                    idVal = "off_${System.currentTimeMillis()}",
                                    title = title,
                                    subtitle = subtitle,
                                    originalPrice = orig,
                                    discountedPrice = disc,
                                    discountAmount = (orig - disc).coerceAtLeast(0.0),
                                    isActive = true
                                )
                                scope.launch {
                                    try { api.createOffer(newOff) } catch (_: Exception) {}
                                    offers = listOf(newOff) + offers
                                    showCreateDialog = false
                                    Toast.makeText(context, "Scheme created!", Toast.LENGTH_SHORT).show()
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Text("Save Scheme", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }
    }
}
