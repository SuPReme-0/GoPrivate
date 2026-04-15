@file:Suppress("unused")

package com.goprivate.app.ui.adapters

import android.annotation.SuppressLint
import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.goprivate.app.R
import com.goprivate.app.data.model.ThreatLog
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import androidx.core.graphics.toColorInt

/**
 * 🛡️ THE TRINITY ADAPTER
 * Features Dual-Axis Styling:
 * Left Icon colored by Engine (A/B/C). Right text colored by Risk (Safe/Suspicious/Malicious).
 */
class ThreatLogAdapter(
    private val onThreatClick: (ThreatLog) -> Unit
) : ListAdapter<ThreatLog, ThreatLogAdapter.ThreatViewHolder>(ThreatDiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ThreatViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_threat_log_cyber, parent, false)
        return ThreatViewHolder(view, onThreatClick)
    }

    override fun onBindViewHolder(holder: ThreatViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    class ThreatViewHolder(
        itemView: View,
        private val onThreatClick: (ThreatLog) -> Unit
    ) : RecyclerView.ViewHolder(itemView) {

        private val threatTypeIcon: View = itemView.findViewById(R.id.threat_type_icon)
        private val appName: TextView = itemView.findViewById(R.id.threat_app_name)
        private val threatType: TextView = itemView.findViewById(R.id.threat_type)
        private val riskScore: TextView = itemView.findViewById(R.id.threat_risk_score)
        private val timestamp: TextView = itemView.findViewById(R.id.threat_timestamp)
        private val action: TextView = itemView.findViewById(R.id.threat_action)
        private val context: Context = itemView.context

        @SuppressLint("SetTextI18n")
        fun bind(threat: ThreatLog) {
            itemView.setOnClickListener { onThreatClick(threat) }

            appName.text = threat.appName
            threatType.text = threat.threatType

            // 🚨 AXIS 1: RISK SCORE STYLING (Right Side)
            val percentage = (threat.riskScore * 100).toInt()
            riskScore.text = "$percentage%"

            when {
                threat.riskScore >= 0.75f -> riskScore.setTextColor(ContextCompat.getColor(context, R.color.alert_red_primary))
                threat.riskScore >= 0.40f -> riskScore.setTextColor("#FFAA00".toColorInt()) // Amber
                else -> riskScore.setTextColor(ContextCompat.getColor(context, R.color.neon_cyan_primary)) // Safe Cyan
            }

            // 🚨 AXIS 2: ENGINE STYLING (Left Side)
            when {
                threat.threatType.contains("Network", ignoreCase = true) || threat.threatType.contains("C2", ignoreCase = true) -> {
                    action.text = "[ NET_LOG ]"
                    val cyan = ContextCompat.getColor(context, R.color.neon_cyan_primary)
                    action.setTextColor(cyan)
                    threatTypeIcon.setBackgroundColor(cyan)
                }
                threat.threatType.contains("Privacy", ignoreCase = true) || threat.threatType.contains("Data", ignoreCase = true) -> {
                    action.text = "[ NLP_LOG ]"
                    val orange = "#FFAA00".toColorInt()
                    action.setTextColor(orange)
                    threatTypeIcon.setBackgroundColor(orange)
                }
                else -> {
                    action.text = "[ SYS_LOG ]"
                    val red = ContextCompat.getColor(context, R.color.alert_red_primary)
                    action.setTextColor(red)
                    threatTypeIcon.setBackgroundColor(red)
                }
            }

            val formatter = SimpleDateFormat("MMM dd, HH:mm:ss", Locale.getDefault())
            timestamp.text = formatter.format(Date(threat.timestamp))
        }
    }

    class ThreatDiffCallback : DiffUtil.ItemCallback<ThreatLog>() {
        override fun areItemsTheSame(oldItem: ThreatLog, newItem: ThreatLog): Boolean {
            return oldItem.timestamp == newItem.timestamp
        }
        override fun areContentsTheSame(oldItem: ThreatLog, newItem: ThreatLog): Boolean {
            return oldItem == newItem
        }
    }
}