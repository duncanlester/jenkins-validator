@Library('shared-library') _

pipeline {
    agent any
    
    parameters {
        choice(
            name: 'REPORT_FORMAT',
            choices: ['html', 'json', 'xml', 'all'],
            description: 'Report format to generate'
        )
    }
    
    triggers {
        cron('0 2 * * *')
    }
    
    stages {
        stage('Fetch Plugins') {
            steps {
                script {
                    echo "📦 Fetching installed Jenkins plugins..."
                    
                    // Get all plugins using Jenkins API
                    def jenkins = Jenkins.instance
                    def pluginManager = jenkins.pluginManager
                    def plugins = pluginManager.plugins
                    
                    env.PLUGIN_DATA = groovy.json.JsonOutput.toJson(
                        plugins.collect { plugin ->
                            [
                                shortName: plugin.shortName,
                                longName: plugin.longName,
                                version: plugin.version,
                                enabled: plugin.enabled,
                                active: plugin.active,
                                hasUpdate: plugin.hasUpdate(),
                                url: plugin.url,
                                dependencies: plugin.dependencies.collect { dep ->
                                    [
                                        shortName: dep.shortName,
                                        version: dep.version,
                                        optional: dep.optional
                                    ]
                                }
                            ]
                        }
                    )
                    
                    writeFile file: 'plugins.json', text: env.PLUGIN_DATA
                    archiveArtifacts artifacts: 'plugins.json'
                    
                    echo "✅ Found ${plugins.size()} plugins"
                }
            }
        }
        
        stage('Check for Updates') {
            steps {
                script {
                    def pluginData = readJSON text: env.PLUGIN_DATA
                    def outdatedPlugins = pluginData.findAll { it.hasUpdate }
                    
                    echo "📊 ${outdatedPlugins.size()} plugins have updates available"
                    
                    env.OUTDATED_COUNT = outdatedPlugins.size().toString()
                    env.OUTDATED_PLUGINS = groovy.json.JsonOutput.toJson(outdatedPlugins)
                }
            }
        }
        
        stage('Scan for Known Vulnerabilities') {
            steps {
                script {
                    echo "🔍 Scanning for known vulnerable plugin versions..."
                    
                    def pluginData = readJSON text: env.PLUGIN_DATA
                    def vulnerabilities = []
                    
                    // Known vulnerable plugins (can be loaded from external source)
                    def knownVulnerabilities = [
                        [plugin: 'script-security', version: '1.75', cve: 'CVE-2021-21642', severity: 'CRITICAL'],
                        [plugin: 'git', version: '4.7.0', cve: 'CVE-2021-21670', severity: 'HIGH'],
                        [plugin: 'pipeline-groovy-lib', version: '564.ve62ca_4e2f61e', cve: 'CVE-2022-34177', severity: 'HIGH'],
                        // Add more known vulnerabilities
                    ]
                    
                    pluginData.each { plugin ->
                        knownVulnerabilities.each { vuln ->
                            if (plugin.shortName == vuln.plugin && plugin.version == vuln.version) {
                                vulnerabilities << [
                                    plugin: plugin.shortName,
                                    version: plugin.version,
                                    cve: vuln.cve,
                                    severity: vuln.severity,
                                    installed: plugin.version
                                ]
                            }
                        }
                    }
                    
                    env.VULNERABILITIES = groovy.json.JsonOutput.toJson(vulnerabilities)
                    env.VULN_COUNT = vulnerabilities.size().toString()
                    
                    if (vulnerabilities.size() > 0) {
                        currentBuild.result = 'UNSTABLE'
                        echo "⚠️ Found ${vulnerabilities.size()} vulnerable plugins!"
                    } else {
                        echo "✅ No known vulnerabilities detected"
                    }
                }
            }
        }
        
        stage('Calculate Risk Score') {
            steps {
                script {
                    def pluginData = readJSON text: env.PLUGIN_DATA
                    def vulnData = readJSON text: env.VULNERABILITIES
                    
                    // Calculate risk score (0-100)
                    def criticalCount = vulnData.count { it.severity == 'CRITICAL' }
                    def highCount = vulnData.count { it.severity == 'HIGH' }
                    def outdatedCount = Integer.parseInt(env.OUTDATED_COUNT)
                    
                    def riskScore = Math.min(
                        (criticalCount * 40) + 
                        (highCount * 20) + 
                        (outdatedCount * 2),
                        100
                    )
                    
                    def riskRating = riskScore > 70 ? 'CRITICAL' : 
                                    riskScore > 40 ? 'HIGH' :
                                    riskScore > 20 ? 'MEDIUM' : 'LOW'
                    
                    env.RISK_SCORE = riskScore.toString()
                    env.RISK_RATING = riskRating
                    
                    echo "📊 Risk Score: ${riskScore}/100 (${riskRating})"
                }
            }
        }
        
        stage('Generate Report') {
            steps {
                script {
                    echo "📝 Generating validation report..."
                    
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
                            timestamp: new Date().format('yyyy-MM-dd HH:mm:ss UTC'),
                            jenkins_version: Jenkins.instance.version,
                            total_plugins: pluginData.size(),
                            outdated_plugins: Integer.parseInt(env.OUTDATED_COUNT),
                            vulnerabilities: Integer.parseInt(env.VULN_COUNT),
                            risk_score: Integer.parseInt(env.RISK_SCORE),
                            risk_rating: env.RISK_RATING,
                            plugins: pluginData,
                            vulnerable_plugins: vulnData,
                            outdated_plugins_list: outdatedData
                        ])
                    )
                    
                    writeFile file: 'plugin-validation-report.json', text: jsonReport
                    
                    // Archive reports
                    archiveArtifacts artifacts: '*.html,*.json'
                    
                    // Publish HTML report
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: '.',
                        reportFiles: 'plugin-validation-report.html',
                        reportName: 'Plugin Validation Report',
                        reportTitles: 'Jenkins Plugin Security Report'
                    ])
                }
            }
        }
    }
    
    post {
        always {
            script {
                echo "🧹 Cleanup complete"
            }
        }
        
        success {
            script {
                echo "✅ Plugin validation completed successfully!"
                
                slackSend(
                    color: env.RISK_RATING == 'LOW' ? 'good' : 'warning',
                    message: """
                        Jenkins Plugin Validation Report
                        
                        *Status:* ${currentBuild.result}
                        *Total Plugins:* ${readJSON(text: env.PLUGIN_DATA).size()}
                        *Vulnerabilities:* ${env.VULN_COUNT}
                        *Outdated:* ${env.OUTDATED_COUNT}
                        *Risk Score:* ${env.RISK_SCORE}/100 (${env.RISK_RATING})
                        
                        <${env.BUILD_URL}Plugin_20Validation_20Report/|View Report>
                    """.stripIndent()
                )
            }
        }
        
        unstable {
            script {
                echo "⚠️ Vulnerabilities detected!"
                
                slackSend(
                    color: 'danger',
                    message: """
                        ⚠️ SECURITY ALERT: Vulnerable Jenkins Plugins Detected
                        
                        *Vulnerabilities:* ${env.VULN_COUNT}
                        *Risk Score:* ${env.RISK_SCORE}/100 (${env.RISK_RATING})
                        
                        <${env.BUILD_URL}Plugin_20Validation_20Report/|View Full Report>
                    """.stripIndent()
                )
            }
        }
    }
}

// HTML Report Generator Function
def generateHTMLReport(plugins, vulnerabilities, outdated, riskScore, riskRating) {
    def timestamp = new Date().format('yyyy-MM-dd HH:mm:ss UTC')
    
    return """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Jenkins Plugin Validation Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .header h1 { font-size: 32px; margin-bottom: 10px; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .stat-card h3 {
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        .stat-card .value {
            font-size: 36px;
            font-weight: bold;
            color: #333;
        }
        .risk-critical { color: #dc3545; }
        .risk-high { color: #fd7e14; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #28a745; }
        .section {
            background: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .section h2 {
            margin-bottom: 20px;
            color: #333;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th {
            background: #f8f9fa;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #dee2e6;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #dee2e6;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
        }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #28a745; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Jenkins Plugin Validation Report</h1>
            <p>Generated: ${timestamp}</p>
            <p>Jenkins Version: ${Jenkins.instance.version}</p>
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
            <table>
                <thead>
                    <tr>
                        <th>Plugin</th>
                        <th>Version</th>
                        <th>CVE</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
                    ${vulnerabilities.collect { vuln -> """
                    <tr>
                        <td><strong>${vuln.plugin}</strong></td>
                        <td>${vuln.version}</td>
                        <td>${vuln.cve}</td>
                        <td><span class="badge badge-${vuln.severity.toLowerCase()}">${vuln.severity}</span></td>
                    </tr>
                    """ }.join('')}
                </tbody>
            </table>
        </div>
        """ : '<div class="section"><h2>✅ No Vulnerabilities Detected</h2></div>'}
        
        ${outdated.size() > 0 ? """
        <div class="section">
            <h2>📦 Plugins With Available Updates</h2>
            <table>
                <thead>
                    <tr>
                        <th>Plugin</th>
                        <th>Current Version</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    ${outdated.collect { plugin -> """
                    <tr>
                        <td><strong>${plugin.longName}</strong></td>
                        <td>${plugin.version}</td>
                        <td><span class="badge badge-medium">UPDATE AVAILABLE</span></td>
                    </tr>
                    """ }.join('')}
                </tbody>
            </table>
        </div>
        """ : ''}
        
        <div class="section">
            <h2>📋 All Installed Plugins (${plugins.size()})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Plugin</th>
                        <th>Version</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    ${plugins.collect { plugin -> """
                    <tr>
                        <td><strong>${plugin.longName}</strong></td>
                        <td>${plugin.version}</td>
                        <td>
                            ${plugin.enabled ? '<span class="badge badge-low">ENABLED</span>' : '<span class="badge">DISABLED</span>'}
                        </td>
                    </tr>
                    """ }.join('')}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
}