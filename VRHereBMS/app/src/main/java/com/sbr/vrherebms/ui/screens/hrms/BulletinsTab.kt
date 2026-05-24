package com.sbr.vrherebms.ui.screens.hrms

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.HrmsViewModel

@Composable
fun BulletinsTab(viewModel: HrmsViewModel) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Text("Announcements Board", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
        }

        if (viewModel.notices.isEmpty()) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color.White)
                ) {
                    Box(modifier = Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
                        Text("No active announcements.", color = Color.Gray, fontSize = 13.sp)
                    }
                }
            }
        } else {
            items(viewModel.notices) { notice ->
                NoticeCard(notice)
            }
        }

        item {
            Spacer(modifier = Modifier.height(8.dp))
            Text("Holiday Calendar", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
        }

        if (viewModel.holidays.isEmpty()) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color.White)
                ) {
                    Box(modifier = Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
                        Text("No upcoming holidays.", color = Color.Gray, fontSize = 13.sp)
                    }
                }
            }
        } else {
            items(viewModel.holidays) { holiday ->
                HolidayCard(holiday)
            }
        }
    }
}
