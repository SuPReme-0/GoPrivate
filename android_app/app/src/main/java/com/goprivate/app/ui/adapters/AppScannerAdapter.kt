@file:Suppress("SetTextI18n")

package com.goprivate.app.ui.adapters

import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.progressindicator.LinearProgressIndicator
import com.goprivate.app.R
import com.goprivate.app.data.ml.EngineBStaticManager
import com.goprivate.app.data.model.AppScanResult

class AppScannerAdapter(
    private val onItemClick: (AppScanResult) -> Unit,
    private val onScanClick: (AppScanResult) -> Unit
) : ListAdapter<AppScanResult, AppScannerAdapter.AppViewHolder>(DiffCallback()) {

    // Tracks the package currently being scanned by Engine B
    private var activeScanningPackage: String? = null

    /**
     * 🚨 PERFORMANCE FIX: Targeted UI Refresh.
     * Prevents the entire list from flashing when only one app updates.
     */
    fun setScanningPackage(packageName: String?) {
        val oldPackage = activeScanningPackage
        activeScanningPackage = packageName

        val currentList = currentList
        val oldIndex = currentList.indexOfFirst { it.packageName == oldPackage }
        val newIndex = currentList.indexOfFirst { it.packageName == packageName }

        if (oldIndex != -1) notifyItemChanged(oldIndex)
        if (newIndex != -1) notifyItemChanged(newIndex)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): AppViewHolder {
        // 🚨 WIRING FIX: Assumes your row layout is named item_app_scan.xml
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_app_scanner_cyber, parent, false)
        return AppViewHolder(view)
    }

    override fun onBindViewHolder(holder: AppViewHolder, position: Int) {
        val app = getItem(position)
        val isScanning = app.packageName == activeScanningPackage
        holder.bind(app, isScanning)
    }

    inner class AppViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {

        private val appName: TextView = itemView.findViewById(R.id.app_name)
        private val packageName: TextView = itemView.findViewById(R.id.package_name) // 🚨 ADDED
        private val riskIndicator: View = itemView.findViewById(R.id.risk_indicator)
        private val riskScore: TextView = itemView.findViewById(R.id.risk_score)
        private val scanStatus: TextView = itemView.findViewById(R.id.scan_status)
        private val scanButton: Button = itemView.findViewById(R.id.scan_button)
        private val scanProgress: LinearProgressIndicator = itemView.findViewById(R.id.item_scan_progress)
        private val context: Context = itemView.context

        init {
            // 🚨 VERSION COMPATIBILITY FIX: Reverted to adapterPosition
            // for compatibility with older RecyclerView dependencies.
            itemView.setOnClickListener {
                @Suppress("DEPRECATION")
                val position = adapterPosition
                if (position != RecyclerView.NO_POSITION) onItemClick(getItem(position))
            }

            scanButton.setOnClickListener {
                @Suppress("DEPRECATION")
                val position = adapterPosition
                if (position != RecyclerView.NO_POSITION) onScanClick(getItem(position))
            }
        }

        fun bind(app: AppScanResult, isScanning: Boolean) {
            appName.text = app.appName
            packageName.text = app.packageName

            if (isScanning) {
                scanProgress.visibility = View.VISIBLE
                scanStatus.visibility = View.VISIBLE
                scanStatus.text = "[ AUDITING_MODULE... ]"
                scanStatus.setTextColor(ContextCompat.getColor(context, R.color.neon_cyan_primary))
                riskScore.visibility = View.GONE // Hide score to prevent visual clutter
                scanButton.text = "SCANNING"
                scanButton.isEnabled = false
                itemView.alpha = 1.0f
                riskIndicator.setBackgroundColor(ContextCompat.getColor(context, R.color.terminal_text_dim))
            } else {
                scanProgress.visibility = View.GONE
                scanButton.isEnabled = true

                if (app.scanTimestamp == 0L) {
                    riskIndicator.setBackgroundColor(ContextCompat.getColor(context, R.color.terminal_text_dim))
                    riskScore.visibility = View.GONE
                    scanStatus.visibility = View.GONE
                    scanButton.text = "AUDIT"
                    itemView.alpha = 1.0f
                } else {
                    riskScore.visibility = View.VISIBLE
                    scanStatus.visibility = View.VISIBLE
                    riskScore.text = "${(app.riskScore * 100).toInt()}%"
                    scanButton.text = "RE-AUDIT"

                    // Dim safe apps slightly to highlight threats
                    itemView.alpha = 0.8f

                    if (app.riskScore < 0.4f) {
                        riskIndicator.setBackgroundColor(ContextCompat.getColor(context, R.color.status_safe))
                        riskScore.setTextColor(ContextCompat.getColor(context, R.color.status_safe))
                        scanStatus.text = "[ SAFE_MODULE ]"
                        scanStatus.setTextColor(ContextCompat.getColor(context, R.color.status_safe))
                    } else if (app.riskScore < EngineBStaticManager.MALICIOUS_THRESHOLD) {
                        riskIndicator.setBackgroundColor(ContextCompat.getColor(context, R.color.status_suspicious))
                        riskScore.setTextColor(ContextCompat.getColor(context, R.color.status_suspicious))
                        scanStatus.text = "[ SUSPICIOUS ]"
                        scanStatus.setTextColor(ContextCompat.getColor(context, R.color.status_suspicious))
                        itemView.alpha = 1.0f
                    } else {
                        riskIndicator.setBackgroundColor(ContextCompat.getColor(context, R.color.status_malicious))
                        riskScore.setTextColor(ContextCompat.getColor(context, R.color.status_malicious))
                        scanStatus.text = "[ CRITICAL_THREAT ]"
                        scanStatus.setTextColor(ContextCompat.getColor(context, R.color.status_malicious))
                        itemView.alpha = 1.0f // Keep malicious fully bright
                    }
                }
            }
        }
    }

    private class DiffCallback : DiffUtil.ItemCallback<AppScanResult>() {
        override fun areItemsTheSame(oldItem: AppScanResult, newItem: AppScanResult) = oldItem.packageName == newItem.packageName
        override fun areContentsTheSame(oldItem: AppScanResult, newItem: AppScanResult) = oldItem == newItem
    }
}