package com.sbr.vrherebms.ui.screens.hrms

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sbr.vrherebms.viewmodel.HrmsViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HrmsEmployeeScreen(
    viewModel: HrmsViewModel = viewModel(),
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var selectedTab by remember { mutableStateOf(0) }

    // Fetch initial datasets on mount
    LaunchedEffect(Unit) {
        viewModel.fetchMyLeaves()
        viewModel.fetchBulletins()
    }

    // Monitor VM events
    LaunchedEffect(key1 = viewModel.uiEvent) {
        viewModel.uiEvent.collect { event ->
            when (event) {
                is HrmsViewModel.UiEvent.ShowToast -> {
                    Toast.makeText(context, event.message, Toast.LENGTH_LONG).show()
                }
                HrmsViewModel.UiEvent.LeaveSubmitted -> {
                    // Trigger refresh
                    viewModel.fetchMyLeaves()
                }
                else -> {}
            }
        }
    }

    Column(modifier = modifier.fillMaxSize().background(Color(0xFFF8FAFC))) {
        // Tab Layout
        TabRow(
            selectedTabIndex = selectedTab,
            containerColor = Color.White,
            contentColor = Color(0xFF4F46E5)
        ) {
            Tab(
                selected = selectedTab == 0,
                onClick = { selectedTab = 0 },
                text = { Text("Bulletins & Holidays", fontWeight = FontWeight.Bold) }
            )
            Tab(
                selected = selectedTab == 1,
                onClick = { selectedTab = 1 },
                text = { Text("Leaves Portal", fontWeight = FontWeight.Bold) }
            )
        }

        Box(modifier = Modifier.fillMaxSize().padding(16.dp)) {
            if (viewModel.isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.align(Alignment.Center),
                    color = Color(0xFF4F46E5)
                )
            } else {
                when (selectedTab) {
                    0 -> BulletinsTab(viewModel)
                    1 -> LeavesTab(viewModel)
                }
            }
        }
    }
}
