#!/usr/bin/env groovy

def generateReports() {
    echo "📝 Generating validation reports..."
    
    def pluginData = readJSON text: env.PLUGIN_DATA
    def vulnData = readJSON text: env.VULNERABILITIES
    def outdatedData = readJSON text: env.OUTDATED_PLUGINS
    
    echo "📊 Generating report for ${pluginData.size()} plugins with full metadata"
    
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
    }
    
    echo "✅ Reports generated successfully!"
}

def sendSuccessNotification() {
    echo "✅ Plugin validation completed successfully!"
}

def sendSecurityAlert() {
    if (currentBuild.result == 'UNSTABLE') {
        echo "⚠️ Vulnerabilities detected!"
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
    
    def pluginsJson = groovy.json.JsonOutput.toJson(plugins)
    
    return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Jenkins Plugin Validation Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; padding: 20px; line-height: 1.6; }
        .container { max-width: 1800px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 12px; margin-bottom: 30px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
        .header h1 { font-size: 36px; margin-bottom: 10px; font-weight: 700; }
        .header p { font-size: 16px; opacity: 0.95; margin: 5px 0; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); transition: transform 0.2s; }
        .stat-card:hover { transform: translateY(-4px); }
        .stat-card h3 { color: #666; font-size: 13px; text-transform: uppercase; margin-bottom: 12px; font-weight: 600; }
        .stat-card .value { font-size: 42px; font-weight: 700; color: #333; }
        .risk-critical { color: #dc3545; }
        .risk-high { color: #fd7e14; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #28a745; }
        .section { background: white; padding: 30px; border-radius: 12px; margin-bottom: 25px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .section h2 { margin-bottom: 20px; color: #333; font-size: 24px; font-weight: 700; }
        .table-container { overflow-x: auto; margin-top: 20px; }
        table { width: 100%; border-collapse: collapse; font-size: 12px; }
        thead { position: sticky; top: 0; z-index: 10; background: #f8f9fa; }
        th { background: #f8f9fa; padding: 10px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid #dee2e6; color: #495057; font-size: 11px; text-transform: uppercase; white-space: nowrap; }
        td { padding: 10px 8px; border-bottom: 1px solid #e9ecef; color: #495057; }
        tr:hover { background: #f8f9fa; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 10px; font-size: 9px; font-weight: 600; text-transform: uppercase; white-space: nowrap; }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: #212529; }
        .badge-low { background: #28a745; color: white; }
        .badge-enabled { background: #28a745; color: white; }
        .badge-disabled { background: #6c757d; color: white; }
        .badge-update { background: #17a2b8; color: white; }
        .pagination { display: flex; justify-content: space-between; align-items: center; margin-top: 20px; padding-top: 20px; border-top: 2px solid #e9ecef; }
        .pagination-info { color: #666; font-size: 14px; font-weight: 500; }
        .pagination-controls { display: flex; gap: 10px; }
        .pagination button { padding: 10px 20px; border: 2px solid #e9ecef; background: white; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 500; transition: all 0.2s; }
        .pagination button:hover:not(:disabled) { background: #667eea; color: white; border-color: #667eea; }
        .pagination button:disabled { opacity: 0.4; cursor: not-allowed; }
        a { color: #667eea; text-decoration: none; font-weight: 500; font-size: 11px; }
        a:hover { text-decoration: underline; }
        code { background: #f8f9fa; padding: 2px 6px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 11px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Jenkins Plugin Validation Report</h1>
            <p><strong>Generated:</strong> ${timestamp} UTC</p>
            <p><strong>Jenkins Version:</strong> ${jenkins.version}</p>
            <p><strong>Scan Source:</strong> Jenkins Update Center (Live)</p>
            <p><strong>By:</strong> duncanlesternot</p>
        </div>
        
        <div class="stats">
            <div class="stat-card"><h3>Total Plugins</h3><div class="value">${plugins.size()}</div></div>
            <div class="stat-card"><h3>Vulnerabilities</h3><div class="value risk-${riskRating.toLowerCase()}">${vulnerabilities.size()}</div></div>
            <div class="stat-card"><h3>Outdated</h3><div class="value">${outdated.size()}</div></div>
            <div class="stat-card"><h3>Risk Score</h3><div class="value risk-${riskRating.toLowerCase()}">${riskScore}/100</div><span class="badge badge-${riskRating.toLowerCase()}">${riskRating}</span></div>
        </div>
        
        ${vulnerabilities.size() > 0 ? """
        <div class="section">
            <h2>🚨 Vulnerable Plugins (${vulnerabilities.size()})</h2>
            <table><thead><tr><th>Plugin</th><th>Version</th><th>CVE</th><th>Severity</th><th>Description</th><th>Link</th></tr></thead>
            <tbody>${vulnerabilities.collect { v -> "<tr><td><strong>${v.plugin}</strong></td><td>${v.version}</td><td>${v.cve}</td><td><span class='badge badge-${v.severity.toLowerCase()}'>${v.severity}</span></td><td>${v.description ?: 'N/A'}</td><td>${v.url ? "<a href='"+v.url+"' target='_blank'>View</a>" : '-'}</td></tr>" }.join('')}</tbody></table>
        </div>
        """ : '<div class="section"><h2>✅ No Vulnerabilities</h2><p>All plugins are secure.</p></div>'}
        
        <div class="section">
            <h2>📋 All Plugins (${plugins.size()})</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Plugin Name</th>
                            <th>Short Name</th>
                            <th>Version</th>
                            <th>Status</th>
                            <th>Active</th>
                            <th>Bundled</th>
                            <th>Pinned</th>
                            <th>URL</th>
                            <th>SCM</th>
                            <th>Wiki</th>
                            <th>Issues</th>
                            <th>Developers</th>
                            <th>Categories</th>
                            <th>Build Date</th>
                            <th>Built By</th>
                            <th>Jenkins Ver</th>
                            <th>Required Core</th>
                            <th>Dependencies</th>
                            <th>Excerpt</th>
                        </tr>
                    </thead>
                    <tbody id="tbody"></tbody>
                </table>
            </div>
            <div class="pagination">
                <div class="pagination-info" id="info"></div>
                <div class="pagination-controls">
                    <button onclick="page=1;render()">First</button>
                    <button onclick="page--;render()">Previous</button>
                    <button onclick="page++;render()">Next</button>
                    <button onclick="page=totalPages;render()">Last</button>
                </div>
            </div>
        </div>
    </div>
    <script>
        const data = ${pluginsJson};
        let page = 1;
        const perPage = 50;
        const totalPages = Math.ceil(data.length / perPage);
        
        console.log("Loaded", data.length, "plugins");
        
        function render() {
            if (page < 1) page = 1;
            if (page > totalPages) page = totalPages;
            
            const start = (page - 1) * perPage;
            const end = start + perPage;
            const pageData = data.slice(start, end);
            
            document.getElementById('tbody').innerHTML = pageData.map(p => 
                "<tr>" +
                "<td><strong>" + esc(p.longName) + "</strong></td>" +
                "<td><code>" + esc(p.shortName) + "</code></td>" +
                "<td>" + esc(p.version) + "</td>" +
                "<td><span class='badge badge-" + (p.enabled ? "enabled'>ENABLED" : "disabled'>DISABLED") + "</span></td>" +
                "<td>" + (p.active ? "✅" : "❌") + "</td>" +
                "<td>" + (p.bundled ? "✅" : "❌") + "</td>" +
                "<td>" + (p.pinned ? "📌" : "❌") + "</td>" +
                "<td>" + (p.url ? "<a href='" + p.url + "' target='_blank'>↗</a>" : "-") + "</td>" +
                "<td>" + (p.scm ? "<a href='" + p.scm + "' target='_blank'>↗</a>" : "-") + "</td>" +
                "<td>" + (p.wiki ? "<a href='" + p.wiki + "' target='_blank'>↗</a>" : "-") + "</td>" +
                "<td>" + (p.issueTrackerUrl ? "<a href='" + p.issueTrackerUrl + "' target='_blank'>↗</a>" : "-") + "</td>" +
                "<td>" + esc(p.developerNames || "Unknown") + "</td>" +
                "<td>" + esc(p.categoryNames || "-") + "</td>" +
                "<td>" + esc(p.buildDate || "-") + "</td>" +
                "<td>" + esc(p.builtBy || "-") + "</td>" +
                "<td>" + esc(p.jenkinsVersion || "-") + "</td>" +
                "<td>" + esc(p.requiredCore || "-") + "</td>" +
                "<td>" + (p.dependencyCount || 0) + "</td>" +
                "<td>" + esc((p.excerpt || "").substring(0, 50)) + "</td>" +
                "</tr>"
            ).join('');
            
            document.getElementById('info').textContent = 
                "Showing " + (start + 1) + "-" + Math.min(end, data.length) + 
                " of " + data.length + " plugins (Page " + page + " of " + totalPages + ")";
        }
        
        function esc(str) {
            if (!str) return '';
            const div = document.createElement('div');
            div.textContent = str.toString();
            return div.innerHTML;
        }
        
        render();
    </script>
</body>
</html>"""
}
