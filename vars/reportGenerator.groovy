#!/usr/bin/env groovy

def generateReports() {
    echo "📝 Generating validation reports..."
    
    def pluginData = readJSON text: env.PLUGIN_DATA
    def vulnData = readJSON text: env.VULNERABILITIES
    def outdatedData = readJSON text: env.OUTDATED_PLUGINS
    
    echo "📊 Generating report for ${pluginData.size()} plugins"
    
    // Generate simple JSON report
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
            plugins: pluginData,
            vulnerable_plugins: vulnData,
            outdated_plugins_list: outdatedData
        ])
    )
    
    writeFile file: 'plugin-validation-report.json', text: jsonReport
    
    // Generate HTML report WITHOUT accessing plugin objects
    generateHTMLFromJSON(pluginData, vulnData, outdatedData)
    
    archiveArtifacts artifacts: '*.html,*.json'
    
    try {
        publishHTML([
            allowMissing: false,
            alwaysLinkToLastBuild: true,
            keepAll: true,
            reportDir: '.',
            reportFiles: 'plugin-validation-report.html',
            reportName: 'Plugin Validation Report'
        ])
    } catch (Exception e) {
        echo "⚠️ HTML Publisher not available"
    }
    
    echo "✅ Reports generated successfully!"
}

def generateHTMLFromJSON(plugins, vulnerabilities, outdated) {
    def timestamp = new Date().format('yyyy-MM-dd HH:mm:ss', TimeZone.getTimeZone('UTC'))
    def jenkinsVersion = Jenkins.instance.version.toString()
    
    def html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Jenkins Plugin Validation Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; padding: 20px; }
        .container { max-width: 1800px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 12px; margin-bottom: 30px; }
        .header h1 { font-size: 36px; margin-bottom: 10px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .stat-card h3 { color: #666; font-size: 13px; text-transform: uppercase; margin-bottom: 12px; }
        .stat-card .value { font-size: 42px; font-weight: 700; }
        .section { background: white; padding: 30px; border-radius: 12px; margin-bottom: 25px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .section h2 { margin-bottom: 20px; font-size: 24px; }
        table { width: 100%; border-collapse: collapse; font-size: 12px; }
        th { background: #f8f9fa; padding: 10px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid #dee2e6; font-size: 11px; text-transform: uppercase; }
        td { padding: 10px 8px; border-bottom: 1px solid #e9ecef; }
        tr:hover { background: #f8f9fa; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 10px; font-size: 9px; font-weight: 600; text-transform: uppercase; }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: #212529; }
        .badge-enabled { background: #28a745; color: white; }
        .badge-disabled { background: #6c757d; color: white; }
        .pagination { display: flex; justify-content: space-between; margin-top: 20px; padding-top: 20px; border-top: 2px solid #e9ecef; }
        .pagination button { padding: 10px 20px; border: 2px solid #e9ecef; background: white; border-radius: 8px; cursor: pointer; }
        .pagination button:hover:not(:disabled) { background: #667eea; color: white; }
        .pagination button:disabled { opacity: 0.4; cursor: not-allowed; }
        code { background: #f8f9fa; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 11px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Jenkins Plugin Validation Report</h1>
            <p><strong>Generated:</strong> ${timestamp} UTC</p>
            <p><strong>Jenkins:</strong> ${jenkinsVersion}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card"><h3>Total Plugins</h3><div class="value">${plugins.size()}</div></div>
            <div class="stat-card"><h3>Vulnerabilities</h3><div class="value">${vulnerabilities.size()}</div></div>
            <div class="stat-card"><h3>Outdated</h3><div class="value">${outdated.size()}</div></div>
            <div class="stat-card"><h3>Risk Score</h3><div class="value">${env.RISK_SCORE}/100</div></div>
        </div>
        
        ${vulnerabilities.size() > 0 ? """
        <div class="section">
            <h2>🚨 Vulnerabilities (${vulnerabilities.size()})</h2>
            <table><thead><tr><th>Plugin</th><th>Version</th><th>CVE</th><th>Severity</th><th>Description</th></tr></thead>
            <tbody>${vulnerabilities.collect { v -> "<tr><td><strong>${esc(v.plugin)}</strong></td><td>${esc(v.version)}</td><td>${esc(v.cve)}</td><td><span class='badge badge-${v.severity.toLowerCase()}'>${esc(v.severity)}</span></td><td>${esc(v.description ?: 'N/A')}</td></tr>" }.join('')}</tbody></table>
        </div>
        """ : '<div class="section"><h2>✅ No Vulnerabilities</h2></div>'}
        
        <div class="section">
            <h2>📋 All Plugins (${plugins.size()})</h2>
            <table id="pluginTable">
                <thead>
                    <tr>
                        <th>Plugin Name</th>
                        <th>Short Name</th>
                        <th>Version</th>
                        <th>Status</th>
                        <th>Active</th>
                        <th>Bundled</th>
                        <th>URL</th>
                        <th>Developers</th>
                        <th>Build Date</th>
                        <th>Built By</th>
                        <th>Jenkins Ver</th>
                        <th>Dependencies</th>
                    </tr>
                </thead>
                <tbody id="tbody"></tbody>
            </table>
            <div class="pagination">
                <div id="info"></div>
                <div><button onclick="p=1;r()">First</button><button onclick="p--;r()">Prev</button><button onclick="p++;r()">Next</button><button onclick="p=tp;r()">Last</button></div>
            </div>
        </div>
    </div>
    <script>
        const data = ${groovy.json.JsonOutput.toJson(plugins)};
        let p=1, pp=50, tp=Math.ceil(data.length/pp);
        function r(){
            if(p<1)p=1; if(p>tp)p=tp;
            const s=(p-1)*pp, e=s+pp, pg=data.slice(s,e);
            document.getElementById('tbody').innerHTML=pg.map(x=>
                '<tr><td><strong>'+e(x.longName)+'</strong></td><td><code>'+e(x.shortName)+'</code></td><td>'+e(x.version)+'</td>'+
                '<td><span class="badge badge-'+(x.enabled?'enabled">ENABLED':'disabled">DISABLED')+'</span></td>'+
                '<td>'+(x.active?'✅':'❌')+'</td>'+
                '<td>'+(x.bundled?'✅':'❌')+'</td>'+
                '<td>'+(x.url?'<a href="'+x.url+'" target="_blank">↗</a>':'-')+'</td>'+
                '<td>'+e(x.developerNames||'Unknown')+'</td>'+
                '<td>'+e(x.buildDate||'-')+'</td>'+
                '<td>'+e(x.builtBy||'-')+'</td>'+
                '<td>'+e(x.jenkinsVersion||'-')+'</td>'+
                '<td>'+(x.dependencyCount||0)+'</td></tr>'
            ).join('');
            document.getElementById('info').textContent='Showing '+(s+1)+'-'+Math.min(e,data.length)+' of '+data.length+' (Page '+p+'/'+tp+')';
        }
        function e(s){ const d=document.createElement('div'); d.textContent=s||''; return d.innerHTML; }
        r();
    </script>
</body>
</html>"""
    
    writeFile file: 'plugin-validation-report.html', text: html
}

@NonCPS
private String esc(obj) {
    return obj?.toString()?.replaceAll('<', '&lt;')?.replaceAll('>', '&gt;')?.replaceAll('"', '&quot;') ?: ''
}

def sendSuccessNotification() {
    echo "✅ Plugin validation completed"
}

def sendSecurityAlert() {
    if (currentBuild.result == 'UNSTABLE') {
        echo "⚠️ Vulnerabilities detected"
    }
}

@NonCPS
def checkPluginInstalled(String pluginName) {
    def jenkins = Jenkins.instance
    def plugin = jenkins.pluginManager.getPlugin(pluginName)
    return plugin != null && plugin.isEnabled()
}
