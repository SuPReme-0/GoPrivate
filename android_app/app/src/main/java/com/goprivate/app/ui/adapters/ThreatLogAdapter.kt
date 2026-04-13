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
 * Connects the UI clicks to the Holographic Panel and adds dynamic Engine-based coloring.
 * Built using classic findViewById for strict compiler compatibility.
 */
class ThreatLogAdapter(
    // 🚨 CONTRACT FIX: Accepts the click listener from the Fragment to trigger the Hologram
    private val onThreatClick: (ThreatLog) -> Unit
) : ListAdapter<ThreatLog, ThreatLogAdapter.ThreatViewHolder>(ThreatDiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ThreatViewHolder {
        // Inflate the updated XML layout
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

        // Classic View References
        private val threatTypeIcon: View = itemView.findViewById(R.id.threat_type_icon)
        private val appName: TextView = itemView.findViewById(R.id.threat_app_name)
        private val threatType: TextView = itemView.findViewById(R.id.threat_type)
        private val riskScore: TextView = itemView.findViewById(R.id.threat_risk_score)
        private val timestamp: TextView = itemView.findViewById(R.id.threat_timestamp)
        private val action: TextView = itemView.findViewById(R.id.threat_action)
        private val context: Context = itemView.context

        @SuppressLint("SetTextI18n")
        fun bind(threat: ThreatLog) {
            // 🚨 INTERACTIVITY: Bind the click to the entire item view
            itemView.setOnClickListener { onThreatClick(threat) }

            // Bind basic info
            appName.text = threat.appName
            threatType.text = threat.threatType

            val percentage = (threat.riskScore * 100).toInt()
            riskScore.text = "$percentage%"

            // 🚨 TRINITY UI POLISH: Dynamic Engine-based styling
            when {
                // ENGINE A: Network Traffic
                threat.threatType.contains("Network", ignoreCase = true) || threat.threatType.contains("C2", ignoreCase = true) -> {
                    action.text = "[ NET_DROP ]"
                    val cyan = ContextCompat.getColor(context, R.color.neon_cyan_primary)
                    action.setTextColor(cyan)
                    threatTypeIcon.setBackgroundColor(cyan)
                }
                // ENGINE C: Privacy / NLP
                threat.threatType.contains("Privacy", ignoreCase = true) || threat.threatType.contains("Sharing", ignoreCase = true) || threat.threatType.contains("Data", ignoreCase = true) -> {
                    action.text = "[ NLP_BLOCK ]"
                    val orange = "#FFAA00".toColorInt()
                    action.setTextColor(orange)
                    threatTypeIcon.setBackgroundColor(orange)
                }
                // ENGINE B: Static XAI
                else -> {
                    action.text = "[ SYS_PURGE ]"
                    val red = ContextCompat.getColor(context, R.color.alert_red_primary)
                    action.setTextColor(red)
                    threatTypeIcon.setBackgroundColor(red)
                }
            }

            // Bind Exact Timestamp
            val formatter = SimpleDateFormat("MMM dd, HH:mm", Locale.getDefault())
            timestamp.text = formatter.format(Date(threat.timestamp))

            // Accessibility metadata
            itemView.contentDescription = "Threat: ${threat.appName}, Type: ${threat.threatType}, Action: ${action.text}"
        }
    }

    class ThreatDiffCallback : DiffUtil.ItemCallback<ThreatLog>() {
        override fun areItemsTheSame(oldItem: ThreatLog, newItem: ThreatLog): Boolean {
            // Identifies unique threats by exact timestamp
            return oldItem.timestamp == newItem.timestamp
        }

        override fun areContentsTheSame(oldItem: ThreatLog, newItem: ThreatLog): Boolean {
            return oldItem == newItem
        }
    }
}