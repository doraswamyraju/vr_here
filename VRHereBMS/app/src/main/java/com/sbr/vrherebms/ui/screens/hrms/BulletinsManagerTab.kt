package com.sbr.vrherebms.ui.screens.hrms

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.HrmsViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BulletinsManagerTab(viewModel: HrmsViewModel) {
    var subTab by remember { mutableStateOf(0) } // 0 -> Notices, 1 -> Holidays
    
    // Notice states
    var noticeTitle by remember { mutableStateOf("") }
    var noticeMsg by remember { mutableStateOf("") }
    var noticePriority by remember { mutableStateOf("Medium") }
    var priorityExpanded by remember { mutableStateOf(false) }

    // Holiday states
    var holidayTitle by remember { mutableStateOf("") }
    var holidayDate by remember { mutableStateOf("") }
    var holidayDesc by remember { mutableStateOf("") }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            TabRow(
                selectedTabIndex = subTab,
                containerColor = Color(0xFFF1F5F9),
                divider = {}
            ) {
                Tab(
                    selected = subTab == 0,
                    onClick = { subTab = 0 },
                    text = { Text("Issue Notice", fontSize = 12.sp, fontWeight = FontWeight.Bold) }
                )
                Tab(
                    selected = subTab == 1,
                    onClick = { subTab = 1 },
                    text = { Text("Add Holiday", fontSize = 12.sp, fontWeight = FontWeight.Bold) }
                )
            }
        }

        // Creator form card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    if (subTab == 0) {
                        Text("Create Company Notice", fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))

                        OutlinedTextField(
                            value = noticeTitle,
                            onValueChange = { noticeTitle = it },
                            label = { Text("Headline Title") },
                            modifier = Modifier.fillMaxWidth()
                        )

                        Box {
                            OutlinedTextField(
                                value = noticePriority,
                                onValueChange = {},
                                readOnly = true,
                                label = { Text("Alert Priority") },
                                modifier = Modifier.fillMaxWidth(),
                                trailingIcon = {
                                    Text(
                                        text = "▼",
                                        modifier = Modifier.clickable { priorityExpanded = true }.padding(8.dp),
                                        fontSize = 12.sp
                                    )
                                }
                            )
                            DropdownMenu(expanded = priorityExpanded, onDismissRequest = { priorityExpanded = false }) {
                                listOf("Low", "Medium", "High").forEach { priority ->
                                    DropdownMenuItem(
                                        text = { Text(priority) },
                                        onClick = {
                                            noticePriority = priority
                                            priorityExpanded = false
                                        }
                                    )
                                }
                            }
                        }

                        OutlinedTextField(
                            value = noticeMsg,
                            onValueChange = { noticeMsg = it },
                            label = { Text("Announcement Body Message") },
                            modifier = Modifier.fillMaxWidth(),
                            maxLines = 4
                        )

                        Button(
                            onClick = {
                                if (noticeTitle.isNotEmpty() && noticeMsg.isNotEmpty()) {
                                    viewModel.createNotice(noticeTitle, noticeMsg, noticePriority)
                                    noticeTitle = ""
                                    noticeMsg = ""
                                    noticePriority = "Medium"
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Text("Publish Notice & Alert Staff", fontWeight = FontWeight.Bold)
                        }
                    } else {
                        Text("Declare Public Holiday", fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))

                        OutlinedTextField(
                            value = holidayTitle,
                            onValueChange = { holidayTitle = it },
                            label = { Text("Holiday Occasion") },
                            modifier = Modifier.fillMaxWidth()
                        )

                        OutlinedTextField(
                            value = holidayDate,
                            onValueChange = { holidayDate = it },
                            label = { Text("Holiday Date (YYYY-MM-DD)") },
                            modifier = Modifier.fillMaxWidth()
                        )

                        OutlinedTextField(
                            value = holidayDesc,
                            onValueChange = { holidayDesc = it },
                            label = { Text("Occasion Description") },
                            modifier = Modifier.fillMaxWidth(),
                            maxLines = 3
                        )

                        Button(
                            onClick = {
                                if (holidayTitle.isNotEmpty() && holidayDate.isNotEmpty()) {
                                    viewModel.createHoliday(holidayTitle, holidayDate, holidayDesc)
                                    holidayTitle = ""
                                    holidayDate = ""
                                    holidayDesc = ""
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Text("Register Holiday Calendar", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }

        // List active details with delete action
        item {
            Text("Active Postings", fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
        }

        if (subTab == 0) {
            if (viewModel.notices.isEmpty()) {
                item {
                    Text("No bulletins published.", fontSize = 12.sp, color = Color.Gray)
                }
            } else {
                items(viewModel.notices) { notice ->
                    Box(modifier = Modifier.fillMaxWidth()) {
                        NoticeCard(notice)
                        // Add Delete button
                        Text(
                            text = "🗑️",
                            modifier = Modifier
                                .align(Alignment.TopEnd)
                                .padding(16.dp)
                                .clickable { viewModel.deleteNotice(notice.id) },
                            fontSize = 16.sp
                        )
                    }
                }
            }
        } else {
            if (viewModel.holidays.isEmpty()) {
                item {
                    Text("No registered holidays.", fontSize = 12.sp, color = Color.Gray)
                }
            } else {
                items(viewModel.holidays) { holiday ->
                    Box(modifier = Modifier.fillMaxWidth()) {
                        HolidayCard(holiday)
                        Text(
                            text = "🗑️",
                            modifier = Modifier
                                .align(Alignment.CenterEnd)
                                .padding(end = 24.dp)
                                .clickable { viewModel.deleteHoliday(holiday.id) },
                            fontSize = 16.sp
                        )
                    }
                }
            }
        }
    }
}
