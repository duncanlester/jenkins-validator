#!/usr/bin/env groovy

import org.jenkins.plugins.validator.PDFGenerator

def generateReports() {
    echo "📝 Generating validation reports..."
    
    def pluginData = readJSON text: env.PLUGIN_DATA
    def vulnData = readJSON text: env.VULNERABILITIES
    def outdatedData = readJSON text: env.OUTDATED_PLUGINS
    
    // Generate HTML Report
    def htmlReport = generateHTMLReport(
        pluginData,
        vulnData,
        outdatedData,
        env.RISK_SCORE,
        env.RISK_RATING
    )
    
    writeFile file: 'plugin-validation-report.html', text: htmlReport
    
    // Generate JSON Report
    def jsonReport = groovy.json.JsonOutput.prettyPrint(
        groovy.json.JsonOutput.toJson([
            timestamp: new Date().format('yyyy-MM-dd HH:mm:ss', TimeZone.getTimeZone('UTC')),
            jenkins_version: Jenkins.instance.version.toString(),
            total_plugins: pluginData.size(),
            outdated_plugins: Integer.parseInt(env.OUTDATED_COUNT),
            vulnerabilities: Integer.parseInt(env.VULN_COUNT),
            critical_vulns: Integer.parseInt(env.CRITICAL_COUNT),
            high_vulns: Integer.parseInt(env.HIGH_COUNT),
            medium_vulns: Integer.parseInt(env.MEDIUM_COUNT),
            risk_score: Integer.parseInt(env.RISK_SCORE),
            risk_rating: env.RISK_RATING,
            sbom_generated: env.SBOM_GENERATED == 'true',
            scan_source: 'Jenkins Update Center',
            plugins: pluginData,
            vulnerable_plugins: vulnData,
            outdated_plugins_list: outdatedData
        ])
    )
    
    writeFile file: 'plugin-validation-report.json', text: jsonReport
    
    archiveArtifacts artifacts: '*.html,*.json'
    
    try {
        publishHTML([
            allowMissing: false,
            alwaysLinkToLastBuild: true,
            keepAll: true,
            reportDir: '.',
            reportFiles: 'plugin-validation-report.html',
            reportName: 'Plugin Validation Report',
            reportTitles: 'Jenkins Plugin Security Report'
        ])
    } catch (Exception e) {
        echo "⚠️ HTML Publisher not available: ${e.message}"
        echo "💡 Install 'HTML Publisher Plugin' to view reports in Jenkins UI"
    }
    
    echo "✅ Reports generated successfully!"
}

def sendSuccessNotification() {
    echo "✅ Plugin validation completed successfully!"
    
    def hasSlack = checkPluginInstalled('slack')
    
    if (!hasSlack) {
        echo "💡 Slack plugin not installed. Skipping Slack notification."
        echo "💡 Install 'Slack Notification Plugin' to enable Slack alerts"
        return
    }
    
    try {
        def pluginCount = readJSON(text: env.PLUGIN_DATA).size()
        
        slackSend(
            color: env.RISK_RATING == 'LOW' ? 'good' : env.RISK_RATING == 'CRITICAL' ? 'danger' : 'warning',
            message: """
                🔒 Jenkins Plugin Validation Report
                
                *Status:* ${currentBuild.result}
                *Total Plugins:* ${pluginCount}
                *Risk Score:* ${env.RISK_SCORE}/100 (${env.RISK_RATING})
                
                *Vulnerabilities Found:*
                • Critical: ${env.CRITICAL_COUNT}
                • High: ${env.HIGH_COUNT}
                • Medium: ${env.MEDIUM_COUNT}
                
                *Outdated Plugins:* ${env.OUTDATED_COUNT}
                *SBOM:* ${env.SBOM_GENERATED == 'true' ? '✅ Generated' : 'Skipped'}
                
                <${env.BUILD_URL}Plugin_20Validation_20Report/|📊 View Full Report>
            """.stripIndent()
        )
    } catch (Exception e) {
        echo "⚠️ Slack notification failed: ${e.message}"
        echo "💡 Configure Slack webhook in Jenkins: Manage Jenkins → Configure System → Slack"
    }
}

def sendSecurityAlert() {
    if (currentBuild.result != 'UNSTABLE') {
        return
    }
    
    echo "⚠️ Vulnerabilities detected!"
    
    def hasSlack = checkPluginInstalled('slack')
    
    if (!hasSlack) {
        echo "💡 Slack plugin not installed. Skipping security alert."
        return
    }
    
    try {
        slackSend(
            color: 'danger',
            message: """
                🚨 SECURITY ALERT: Vulnerable Jenkins Plugins Detected
                
                *Critical:* ${env.CRITICAL_COUNT}
                *High:* ${env.HIGH_COUNT}
                *Risk Score:* ${env.RISK_SCORE}/100 (${env.RISK_RATING})
                
                <${env.BUILD_URL}Plugin_20Validation_20Report/|🔍 View Full Report>
                
                ⚠️ Immediate action required!
            """.stripIndent()
        )
    } catch (Exception e) {
        echo "⚠️ Security alert via Slack failed: ${e.message}"
    }
}

@NonCPS
def checkPluginInstalled(String pluginName) {
    def jenkins = Jenkins.instance
    def pluginManager = jenkins.pluginManager
    def plugin = pluginManager.getPlugin(pluginName)
    return plugin != null && plugin.isEnabled()
}

@NonCPS
private String generateHTMLReport(plugins, vulnerabilities, outdated, riskScore, riskRating) {
    def timestamp = new Date().format('yyyy-MM-dd HH:mm:ss', TimeZone.getTimeZone('UTC'))
    def jenkins = Jenkins.instance
    
    def pluginsJson = groovy.json.JsonOutput.toJson(plugins).replaceAll('\\\\', '\\\\\\\\').replaceAll("'", "\\\\'")
    def vulnJson = groovy.json.JsonOutput.toJson(vulnerabilities).replaceAll('\\\\', '\\\\\\\\').replaceAll("'", "\\\\'")
    def outdatedJson = groovy.json.JsonOutput.toJson(outdated).replaceAll('\\\\', '\\\\\\\\').replaceAll("'", "\\\\'")
    
    return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Jenkins Plugin Validation Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f5f7fa;
            padding: 20px;
            line-height: 1.6;
        }
        .container { max-width: 1600px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .header h1 { font-size: 36px; margin-bottom: 10px; font-weight: 700; }
        .header p { font-size: 16px; opacity: 0.95; margin: 5px 0; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.15);
        }
        .stat-card h3 {
            color: #666;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
            font-weight: 600;
        }
        .stat-card .value { font-size: 42px; font-weight: 700; color: #333; line-height: 1; }
        .risk-critical { color: #dc3545; }
        .risk-high { color: #fd7e14; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #28a745; }
        .section {
            background: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 25px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .section h2 {
            margin-bottom: 20px;
            color: #333;
            font-size: 24px;
            font-weight: 700;
        }
        .table-container { overflow-x: auto; margin-top: 20px; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        thead { position: sticky; top: 0; z-index: 10; }
        th {
            background: #f8f9fa;
            padding: 12px 10px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #dee2e6;
            color: #495057;
            font-size: 12px;
            text-transform: uppercase;
            white-space: nowrap;
        }
        td { padding: 12px 10px; border-bottom: 1px solid #e9ecef; color: #495057; }
        tr:hover { background: #f8f9fa; }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            white-space: nowrap;
        }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: #212529; }
        .badge-low { background: #28a745; color: white; }
        .badge-enabled { background: #28a745; color: white; }
        .badge-disabled { background: #6c757d; color: white; }
        .badge-update { background: #17a2b8; color: white; }
        .controls {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            align-items: center;
        }
        .search-box { flex: 1; min-width: 250px; }
        .search-box input {
            width: 100%;
            padding: 10px 15px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 14px;
        }
        .search-box input:focus { outline: none; border-color: #667eea; }
        .filter-group { display: flex; gap: 10px; align-items: center; }
        .filter-group label { font-size: 14px; color: #666; font-weight: 500; }
        select {
            padding: 8px 12px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 14px;
            background: white;
            cursor: pointer;
        }
        .pagination {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 2px solid #e9ecef;
        }
        .pagination-info { color: #666; font-size: 14px; }
        .pagination-controls { display: flex; gap: 8px; }
        .pagination button {
            padding: 8px 16px;
            border: 2px solid #e9ecef;
            background: white;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
        }
        .pagination button:hover:not(:disabled) {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }
        .pagination button:disabled { opacity: 0.4; cursor: not-allowed; }
        a { color: #667eea; text-decoration: none; font-weight: 500; }
        a:hover { text-decoration: underline; }
        code {
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }
        .link-badge {
            display: inline-block;
            padding: 3px 8px;
            background: #e9ecef;
            border-radius: 6px;
            font-size: 11px;
            color: #495057;
            text-decoration: none;
            margin-right: 4px;
        }
        .link-badge:hover { background: #667eea; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Jenkins Plugin Validation Report</h1>
            <p><strong>Generated:</strong> ${timestamp} UTC</p>
            <p><strong>Jenkins Version:</strong> ${jenkins.version}</p>
            <p><strong>Scan Source:</strong> Jenkins Update Center (Live)</p>
            <p><strong>Report By:</strong> duncanlester</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Total Plugins</h3>
                <div class="value">${plugins.size()}</div>
            </div>
            <div class="stat-card">
                <h3>Vulnerabilities</h3>
                <div class="value risk-${riskRating.toLowerCase()}">${vulnerabilities.size()}</div>
            </div>
            <div class="stat-card">
                <h3>Outdated</h3>
                <div class="value">${outdated.size()}</div>
            </div>
            <div class="stat-card">
                <h3>Risk Score</h3>
                <div class="value risk-${riskRating.toLowerCase()}">${riskScore}/100</div>
                <span class="badge badge-${riskRating.toLowerCase()}">${riskRating}</span>
            </div>
        </div>
        
        ${vulnerabilities.size() > 0 ? """
        <div class="section">
            <h2>🚨 Vulnerable Plugins</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Plugin Name</th>
                            <th>Version</th>
                            <th>CVE/Advisory</th>
                            <th>Severity</th>
                            <th>Description</th>
                            <th>Link</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${vulnerabilities.collect { vuln -> """
                        <tr>
                            <td><strong>${vuln.plugin}</strong></td>
                            <td>${vuln.version}</td>
                            <td>${vuln.cve}</td>
                            <td><span class="badge badge-${vuln.severity.toLowerCase()}">${vuln.severity}</span></td>
                            <td>${vuln.description ?: 'N/A'}</td>
                            <td>${vuln.url ? "<a href='${vuln.url}' target='_blank'>View ↗</a>" : 'N/A'}</td>
                        </tr>
                        """ }.join('')}
                    </tbody>
                </table>
            </div>
        </div>
        """ : '<div class="section"><h2>✅ No Vulnerabilities Detected</h2><p>All plugins are secure according to Jenkins Update Center.</p></div>'}
        
        ${outdated.size() > 0 ? """
        <div class="section">
            <h2>📦 Plugins With Available Updates</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Plugin Name</th>
                            <th>Short Name</th>
                            <th>Version</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${outdated.collect { plugin -> """
                        <tr>
                            <td><strong>${plugin.longName}</strong></td>
                            <td><code>${plugin.shortName}</code></td>
                            <td>${plugin.version}</td>
                            <td><span class="badge badge-update">UPDATE AVAILABLE</span></td>
                        </tr>
                        """ }.join('')}
                    </tbody>
                </table>
            </div>
        </div>
        """ : ''}
        
        <div class="section">
            <h2>📋 All Installed Plugins (${plugins.size()})</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Plugin Name</th>
                            <th>Short Name</th>
                            <th>Version</th>
                            <th>Status</th>
                            <th>License</th>
                            <th>Dependencies</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${plugins.collect { plugin -> """
                        <tr>
                            <td><strong>${plugin.longName}</strong></td>
                            <td><code>${plugin.shortName}</code></td>
                            <td>${plugin.version}</td>
                            <td><span class="badge badge-${plugin.enabled ? 'enabled' : 'disabled'}">${plugin.enabled ? 'ENABLED' : 'DISABLED'}</span></td>
                            <td>${plugin.license ?: 'Unknown'}</td>
                            <td>${plugin.dependencies?.size() ?: 0}</td>
                        </tr>
                        """ }.join('')}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>"""
}
