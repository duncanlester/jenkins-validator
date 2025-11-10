#!/usr/bin/env groovy

def fetchInstalledPlugins() {
    echo "📦 Fetching installed Jenkins plugins..."
    
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

def fetchSecurityWarnings() {
    echo "🔍 Checking Jenkins Update Center for security warnings..."
    
    def jenkins = Jenkins.instance
    def updateCenter = jenkins.updateCenter
    def allWarnings = []
    
    updateCenter.sites.each { site ->
        try {
            site.updateDirectlyNow()
            
            if (site.data && site.data.warnings) {
                site.data.warnings.each { warning ->
                    if (warning.type == 'plugin') {
                        allWarnings << [
                            type: warning.type,
                            id: warning.id,
                            name: warning.name,
                            message: warning.message,
                            url: warning.url,
                            versions: warning.versions?.collect { it.pattern }
                        ]
                    }
                }
            }
        } catch (Exception e) {
            echo "⚠️ Could not fetch warnings from ${site.url}: ${e.message}"
        }
    }
    
    env.SECURITY_WARNINGS = groovy.json.JsonOutput.toJson(allWarnings)
    echo "⚠️ Found ${allWarnings.size()} security warnings"
}

def checkForUpdates() {
    def pluginData = readJSON text: env.PLUGIN_DATA
    def outdatedPlugins = pluginData.findAll { it.hasUpdate }
    
    echo "📊 ${outdatedPlugins.size()} plugins have updates available"
    
    env.OUTDATED_COUNT = outdatedPlugins.size().toString()
    env.OUTDATED_PLUGINS = groovy.json.JsonOutput.toJson(outdatedPlugins)
}

def scanVulnerabilities() {
    echo "🔍 Scanning for known vulnerabilities..."
    
    def pluginData = readJSON text: env.PLUGIN_DATA
    def securityWarnings = readJSON text: env.SECURITY_WARNINGS
    def vulnerabilities = []
    
    pluginData.each { plugin ->
        securityWarnings.each { warning ->
            if (warning.name == plugin.shortName) {
                def cveMatch = (warning.id =~ /CVE-\d{4}-\d+/)
                def cve = cveMatch ? cveMatch[0] : warning.id
                
                def severity = determineSeverity(warning.message)
                def cvssScore = getCvssScore(severity)
                
                vulnerabilities << [
                    plugin: plugin.shortName,
                    version: plugin.version,
                    cve: cve,
                    severity: severity,
                    cvss: cvssScore,
                    description: warning.message,
                    url: warning.url,
                    installed: plugin.version
                ]
            }
        }
    }
    
    vulnerabilities = vulnerabilities.unique { [it.plugin, it.cve] }
    
    env.VULNERABILITIES = groovy.json.JsonOutput.toJson(vulnerabilities)
    env.VULN_COUNT = vulnerabilities.size().toString()
    
    if (vulnerabilities.size() > 0) {
        currentBuild.result = 'UNSTABLE'
        echo "⚠️ Found ${vulnerabilities.size()} vulnerable plugins!"
        
        vulnerabilities.each { vuln ->
            echo "  - ${vuln.plugin} ${vuln.version}: ${vuln.cve} (${vuln.severity})"
        }
    } else {
        echo "✅ No known vulnerabilities detected"
    }
}

private def determineSeverity(String message) {
    if (!message) return 'MEDIUM'
    
    def lowerMsg = message.toLowerCase()
    
    if (lowerMsg.contains('critical')) return 'CRITICAL'
    if (lowerMsg.contains('high')) return 'HIGH'
    if (lowerMsg.contains('low')) return 'LOW'
    
    return 'MEDIUM'
}

private def getCvssScore(String severity) {
    switch(severity) {
        case 'CRITICAL': return 9.0
        case 'HIGH': return 7.5
        case 'MEDIUM': return 5.0
        case 'LOW': return 3.0
        default: return 5.0
    }
}
