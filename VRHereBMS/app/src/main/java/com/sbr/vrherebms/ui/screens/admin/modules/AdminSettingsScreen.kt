package com.sbr.vrherebms.ui.screens.admin.modules

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
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
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminSettingsScreen(
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current

    var gstRate by remember { mutableStateOf("18.0") }
    var basePlatformFee by remember { mutableStateOf("150") }
    var sandboxMode by remember { mutableStateOf(true) }
    var emailAlerts by remember { mutableStateOf(true) }
    var webhooksConnected by remember { mutableStateOf(true) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF1F5F9))
    ) {
        // 1. Sleek Command Header
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1B4B))
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Text(
                    text = "SYSTEM SETTINGS CENTER",
                    color = Color(0xFF38BDF8),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.ExtraBold,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Global Controls",
                    color = Color.White,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Manage server variables, statutory base taxes, Razorpay gateway integrations, and staff security indexes.",
                    color = Color(0xFF94A3B8),
                    fontSize = 12.sp,
                    lineHeight = 16.sp
                )
            }
        }

        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Server Node Status Gauge
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFEEF2F6))
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(10.dp)
                                    .background(Color(0xFF10B981), CircleShape)
                            )
                            Column {
                                Text("Server Status: Operational", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = Color(0xFF1E293B))
                                Text("Node: srv875579.vrhere.in (Ping: 14ms)", fontSize = 11.sp, color = Color(0xFF64748B))
                            }
                        }

                        Box(
                            modifier = Modifier
                                .background(Color(0xFFECFDF5), RoundedCornerShape(6.dp))
                                .padding(horizontal = 8.dp, vertical = 2.dp)
                        ) {
                            Text("LIVE", color = Color(0xFF10B981), fontSize = 9.sp, fontWeight = FontWeight.Black)
                        }
                    }
                }
            }

            // Billing Parameters section
            item {
                Text("Billing & Taxation Parameters", color = Color(0xFF1E293B), fontWeight = FontWeight.Bold, fontSize = 15.sp)
            }

            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFEEF2F6))
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        OutlinedTextField(
                            value = gstRate,
                            onValueChange = { gstRate = it },
                            label = { Text("Standard CGST + SGST Rate (%)") },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp)
                        )

                        OutlinedTextField(
                            value = basePlatformFee,
                            onValueChange = { basePlatformFee = it },
                            label = { Text("Platform Filing Conv. Fee (Rs.)") },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp)
                        )
                    }
                }
            }

            // Integrations & webhook configs
            item {
                Text("Payment Gateway & Alert Integrations", color = Color(0xFF1E293B), fontWeight = FontWeight.Bold, fontSize = 15.sp)
            }

            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFEEF2F6))
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        // Toggle 1
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text("Razorpay Sandbox Mode", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = Color(0xFF1E293B))
                                Text("Dispatch mock test orders for checks", fontSize = 11.sp, color = Color(0xFF64748B))
                            }
                            Switch(
                                checked = sandboxMode,
                                onCheckedChange = { sandboxMode = it }
                            )
                        }

                        Divider(color = Color(0xFFF1F5F9))

                        // Toggle 2
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text("Global Webhook Receivers", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = Color(0xFF1E293B))
                                Text("Auto-sync invoice states to servers", fontSize = 11.sp, color = Color(0xFF64748B))
                            }
                            Switch(
                                checked = webhooksConnected,
                                onCheckedChange = { webhooksConnected = it }
                            )
                        }
                    }
                }
            }

            // Save Actions
            item {
                Button(
                    onClick = {
                        Toast.makeText(context, "System configurations saved successfully!", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(52.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Text("Save Configurations", fontWeight = FontWeight.Bold, fontSize = 14.sp)
                }
            }
        }
    }
}
