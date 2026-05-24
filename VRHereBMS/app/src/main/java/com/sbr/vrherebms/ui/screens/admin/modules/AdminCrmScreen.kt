package com.sbr.vrherebms.ui.screens.admin.modules

import android.widget.Toast
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel

data class LeadItem(
    val id: String,
    val name: String,
    val service: String,
    val value: String,
    var stage: String // 'Lead', 'Contacted', 'Quoted', 'Converted'
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminCrmScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var selectedStage by remember { mutableStateOf("Lead") }

    var leadsList by remember {
        mutableStateOf(
            listOf(
                LeadItem("1", "Rajugari Ventures", "Private Limited Company", "Rs. 1,999", "Lead"),
                LeadItem("2", "Sri Navya", "SPICe+ Director DIN KYC", "Rs. 499", "Contacted"),
                LeadItem("3", "Gayatri Enterprises", "Labour / Contract Labour License", "Rs. 1,800", "Lead"),
                LeadItem("4", "Blue Cat Solutions", "GST Return Filing", "Rs. 4,200", "Quoted"),
                LeadItem("5", "Mark & Co", "Income Tax Auditing", "Rs. 4,500", "Converted"),
                LeadItem("6", "Red Capital Corp", "Trademark Objection Reply", "Rs. 2,400", "Contacted")
            )
        )
    }

    val stages = listOf("Lead", "Contacted", "Quoted", "Converted")

    val filteredLeads = remember(selectedStage, leadsList) {
        leadsList.filter { it.stage == selectedStage }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF1F5F9))
    ) {
        // 1. Sleek Purple Command Header
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1B4B))
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Text(
                    text = "CRM CLIENT PIPELINE",
                    color = Color(0xFF38BDF8),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.ExtraBold,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Lead Stages Board",
                    color = Color.White,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Manage incoming inquiries, schedule call backs, dispatch commercial quotes, and track customer conversion rates.",
                    color = Color(0xFF94A3B8),
                    fontSize = 12.sp,
                    lineHeight = 16.sp
                )
            }
        }

        // 2. Stage column selection row
        LazyRow(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(stages) { stageName ->
                val isSelected = selectedStage == stageName
                val count = leadsList.count { it.stage == stageName }
                val stageBg = if (isSelected) Color(0xFF4F46E5) else Color.White
                val textColor = if (isSelected) Color.White else Color(0xFF64748B)

                Box(
                    modifier = Modifier
                        .background(stageBg, RoundedCornerShape(12.dp))
                        .border(
                            1.dp,
                            if (isSelected) Color.Transparent else Color(0xFFE2E8F0),
                            RoundedCornerShape(12.dp)
                        )
                        .clickable { selectedStage = stageName }
                        .padding(horizontal = 14.dp, vertical = 8.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(
                            text = stageName.uppercase(),
                            color = textColor,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Black
                        )
                        Box(
                            modifier = Modifier
                                .size(16.dp)
                                .background(
                                    if (isSelected) Color.White.copy(alpha = 0.2f) else Color(0xFFEFF6FF),
                                    CircleShape
                                ),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = count.toString(),
                                fontSize = 9.sp,
                                color = if (isSelected) Color.White else Color(0xFF3B82F6),
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 3. Lead list column kanban deck
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            items(filteredLeads) { lead ->
                var expandedStageMenu by remember { mutableStateOf(false) }

                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFEEF2F6))
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(36.dp)
                                        .background(Color(0xFFF1F5F9), CircleShape),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        text = lead.name.take(1).uppercase(),
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 15.sp,
                                        color = Color(0xFF475569)
                                    )
                                }

                                Column {
                                    Text(
                                        text = lead.name,
                                        fontSize = 14.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color(0xFF1E293B)
                                    )
                                    Text(
                                        text = lead.service,
                                        fontSize = 11.sp,
                                        color = Color(0xFF64748B),
                                        fontWeight = FontWeight.Medium
                                    )
                                }
                            }

                            Box(
                                modifier = Modifier
                                    .background(Color(0xFFEFF6FF), RoundedCornerShape(8.dp))
                                    .padding(horizontal = 10.dp, vertical = 4.dp)
                            ) {
                                Text(
                                    text = lead.value,
                                    color = Color(0xFF3B82F6),
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Black
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(12.dp))
                        Divider(color = Color(0xFFF1F5F9))
                        Spacer(modifier = Modifier.height(12.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            TextButton(
                                onClick = {
                                    Toast.makeText(context, "Callback scheduled for ${lead.name}", Toast.LENGTH_SHORT).show()
                                },
                                contentPadding = PaddingValues(0.dp)
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                                ) {
                                    Icon(Icons.Default.PhoneCallback, contentDescription = null, modifier = Modifier.size(14.dp))
                                    Text("Schedule Callback", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                }
                            }

                            Box {
                                Button(
                                    onClick = { expandedStageMenu = true },
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = Color(0xFFF1F5F9),
                                        contentColor = Color(0xFF475569)
                                    ),
                                    shape = RoundedCornerShape(8.dp),
                                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                                    modifier = Modifier.height(32.dp)
                                ) {
                                    Text("Move Stage", fontSize = 10.sp, fontWeight = FontWeight.Black)
                                }

                                DropdownMenu(
                                    expanded = expandedStageMenu,
                                    onDismissRequest = { expandedStageMenu = false }
                                ) {
                                    stages.forEach { nextStage ->
                                        DropdownMenuItem(
                                            text = { Text(nextStage) },
                                            onClick = {
                                                leadsList = leadsList.map { old ->
                                                    if (old.id == lead.id) old.copy(stage = nextStage) else old
                                                }
                                                Toast.makeText(context, "Moved lead to stage $nextStage", Toast.LENGTH_SHORT).show()
                                                expandedStageMenu = false
                                            }
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (filteredLeads.isEmpty()) {
                item {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 40.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "No leads in this stage.",
                            color = Color(0xFF64748B),
                            fontSize = 12.sp,
                            textAlign = TextAlign.Center
                        )
                    }
                }
            }
        }
    }
}
