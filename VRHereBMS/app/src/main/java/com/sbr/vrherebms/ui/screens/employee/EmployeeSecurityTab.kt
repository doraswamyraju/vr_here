package com.sbr.vrherebms.ui.screens.employee

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun EmployeeSecurityTab() {
    val rules = listOf(
        "Employee visibility is restricted to explicitly assigned orders, checklists, and task trackers.",
        "Admin-only modifications (such as financial overrides, invoice edits, and global user management) are locked.",
        "Every document status update and timer action is audit-logged to maintain project transparency.",
        "Your authentication token/session is verified dynamically. Logouts are triggered on token expiry."
    )

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "Security & Compliance",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black,
                    color = Color(0xFF1E293B)
                )
                Text(
                    text = "Security guidelines, data rules, and compliance standards.",
                    fontSize = 12.sp,
                    color = Color(0xFF64748B)
                )
            }
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Box(
                        modifier = Modifier
                            .size(64.dp)
                            .background(Color(0xFFEEF2F6), CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null,
                            tint = Color(0xFF6366F1),
                            modifier = Modifier.size(32.dp)
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    Text(
                        text = "VR Here BMS Security Matrix",
                        fontWeight = FontWeight.Black,
                        fontSize = 16.sp,
                        color = Color(0xFF1E293B)
                    )
                    Text(
                        text = "Employee Level Permissions Active",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF10B981),
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
            }
        }

        item {
            Text(
                text = "Authorization Rules",
                fontWeight = FontWeight.Black,
                fontSize = 15.sp,
                color = Color(0xFF1E293B),
                modifier = Modifier.padding(top = 8.dp)
            )
        }

        items(rules.size) { index ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(32.dp)
                            .background(Color(0xFFEEF2F6), RoundedCornerShape(8.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = (index + 1).toString(),
                            fontWeight = FontWeight.Black,
                            fontSize = 12.sp,
                            color = Color(0xFF6366F1)
                        )
                    }
                    Spacer(modifier = Modifier.width(16.dp))
                    Text(
                        text = rules[index],
                        fontSize = 12.sp,
                        color = Color(0xFF475569),
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }

        item {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFFEEF2F6), RoundedCornerShape(12.dp))
                    .padding(12.dp)
            ) {
                Text(
                    text = "System audit logs, permissions mappings, and internal timelines are continuously audited by global Administrators.",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF6366F1)
                )
            }
        }

        item {
            Spacer(modifier = Modifier.height(60.dp))
        }
    }
}
