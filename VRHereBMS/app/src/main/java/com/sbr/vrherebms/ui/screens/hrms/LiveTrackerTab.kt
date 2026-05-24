package com.sbr.vrherebms.ui.screens.hrms

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
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
fun LiveTrackerTab(viewModel: HrmsViewModel) {
    val status = viewModel.liveStatus

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Personnel Tracker Today", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFF1E293B))
                Button(
                    onClick = { viewModel.fetchLiveStatus() },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF1F5F9), contentColor = Color(0xFF475569)),
                    shape = RoundedCornerShape(8.dp),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                ) {
                    Text("🔄 Sync", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }
            }
        }

        // Clocked in employees
        item {
            Text("🟢 Clocked In Working (${status?.clockedIn?.size ?: 0})", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF10B981))
        }

        if (status?.clockedIn.isNullOrEmpty()) {
            item {
                Text("No active working sessions today.", fontSize = 12.sp, color = Color.Gray, modifier = Modifier.padding(start = 8.dp))
            }
        } else {
            items(status!!.clockedIn) { emp ->
                LiveEmployeeCard(emp, isWorking = true)
            }
        }

        // On leave today
        item {
            Text("🔵 On Approved Leave (${status?.onLeave?.size ?: 0})", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF3B82F6))
        }

        if (status?.onLeave.isNullOrEmpty()) {
            item {
                Text("No scheduled leaves today.", fontSize = 12.sp, color = Color.Gray, modifier = Modifier.padding(start = 8.dp))
            }
        } else {
            items(status!!.onLeave) { emp ->
                LiveEmployeeCard(emp, isOnLeave = true)
            }
        }

        // Offline employees
        item {
            Text("⚪ Clocked Out / Offline (${status?.offline?.size ?: 0})", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF64748B))
        }

        if (status?.offline.isNullOrEmpty()) {
            item {
                Text("All staff clocked in or on leave.", fontSize = 12.sp, color = Color.Gray, modifier = Modifier.padding(start = 8.dp))
            }
        } else {
            items(status!!.offline) { emp ->
                LiveEmployeeCard(emp, isOffline = true)
            }
        }
    }
}
