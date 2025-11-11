#!/usr/bin/env groovy

def fetchInstalledPlugins() {
    echo "📦 Fetching installed Jenkins plugins..."
    
    def pluginData = getPluginData()
    
    env.PLUGIN_DATA = groovy.json.JsonOutput.toJson(pluginData)
    
    writeFile file: 'plugins.json', text: env.PLUGIN_DATA
    archiveArtifacts artifacts: 'plugins.json'
    
    echo "✅ Found ${pluginData.size()} plugins"
}

@NonCPS
def getPluginData() {
    def jenkins = Jenkins.instance
    def pluginManager = jenkins.pluginManager
    def plugins = pluginManager.plugins
    
    return plugins.collect { plugin ->
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
}

def fetchSecurityWarnings() {
    echo "🔍 Fetching security warnings - DEEP DEBUG MODE..."
    
    def allWarnings = getSecurityWarningsDebug()
    
    env.SECURITY_WARNINGS = groovy.json.JsonOutput.toJson(allWarnings)
    echo "⚠️ Total warnings collected: ${allWarnings.size()}"
}

@NonCPS
def getSecurityWarningsDebug() {
    def jenkins = Jenkins.instance
    def pluginManager = jenkins.pluginManager
    def updateCenter = jenkins.updateCenter
    def allWarnings = []
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🔍 DEEP DEBUG: Update Center Analysis"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    // Check each plugin for security warnings using PluginManager API
    pluginManager.plugins.each { plugin ->
        try {
            def wrapper = pluginManager.getPlugin(plugin.shortName)
            
            // Check if plugin has security warnings
            def hasWarnings = updateCenter.getPlugin(plugin.shortName)?.hasWarnings()
            
            if (hasWarnings) {
                echo "⚠️ ${plugin.shortName} ${plugin.version} HAS WARNINGS"
                
                // Get the actual warnings for this plugin
                def pluginInfo = updateCenter.getPlugin(plugin.shortName)
                if (pluginInfo) {
                    def warnings = pluginInfo.getWarnings()
                    
                    warnings.each { warning ->
                        echo "   Type: ${warning.type}"
                        echo "   ID: ${warning.id}"
                        echo "   Message: ${warning.message?.take(100)}"
                        
                        allWarnings << [
                            type: warning.type,
                            id: warning.id,
                            name: plugin.shortName,
                            message: warning.message,
                            url: warning.url,
                            active: warning.isActive(),
                            versions: warning.versions?.collect { v -> v.toString() }
                        ]
                    }
                }
            }
        } catch (Exception e) {
            // Continue silently
        }
    }
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    // Also check Update Sites
    echo "🔍 Checking Update Sites..."
    updateCenter.sites.each { site ->
        try {
            echo "📍 Site: ${site.url}"
            
            site.updateDirectlyNow()
            Thread.sleep(3000)
            
            def data = site.getData()
            
            if (data != null) {
                def siteWarnings = data.getWarnings()
                
                if (siteWarnings != null && !siteWarnings.isEmpty()) {
                    echo "   Found ${siteWarnings.size()} warnings in site data"
                    
                    siteWarnings.each { warning ->
                        if (warning.type == 'plugin') {
                            echo "   ⚠️ ${warning.name}: ${warning.id}"
                            
                            allWarnings << [
                                type: warning.type,
                                id: warning.id,
                                name: warning.name,
                                message: warning.message,
                                url: warning.url,
                                versions: warning.versions?.collect { v -> 
                                    [pattern: v.pattern ?: v.toString(), firstVersion: v.firstVersion]
                                }
                            ]
                        }
                    }
                }
            }
        } catch (Exception e) {
            echo "⚠️ Error: ${e.message}"
        }
    }
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    // Deduplicate
    def uniqueWarnings = allWarnings.unique { [it.name, it.id] }
    
    echo "📊 Total unique warnings: ${uniqueWarnings.size()}"
    uniqueWarnings.each { w ->
        echo "   • ${w.name} - ${w.id}"
    }
    
    return uniqueWarnings
}

def checkForUpdates() {
    def pluginData = readJSON text: env.PLUGIN_DATA
    def outdatedPlugins = findOutdatedPlugins(pluginData)
    
    echo "📊 ${outdatedPlugins.size()} plugins have updates available"
    
    env.OUTDATED_COUNT = outdatedPlugins.size().toString()
    env.OUTDATED_PLUGINS = groovy.json.JsonOutput.toJson(outdatedPlugins)
}

@NonCPS
def findOutdatedPlugins(pluginData) {
    return pluginData.findAll { it.hasUpdate }
}

def scanVulnerabilities() {
    echo "🔍 Scanning for vulnerabilities..."
    
    def pluginData = readJSON text: env.PLUGIN_DATA
    def securityWarnings = readJSON text: env.SECURITY_WARNINGS
    def vulnerabilities = []
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🔍 MATCHING: ${pluginData.size()} plugins vs ${securityWarnings.size()} warnings"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    pluginData.each { plugin ->
        def matchingWarnings = securityWarnings.findAll { w -> w.name == plugin.shortName }
        
        if (matchingWarnings.size() > 0) {
            echo "✅ ${plugin.shortName} ${plugin.version} - Found ${matchingWarnings.size()} warning(s)"
            
            matchingWarnings.each { warning ->
                def cveMatch = (warning.id =~ /CVE-\d{4}-\d+/)
                def cve = cveMatch ? cveMatch[0] : warning.id
                
                def severity = determineSeverity(warning.message)
                def cvssScore = getCvssScore(severity)
                
                vulnerabilities << [
                    plugin: plugin.shortName,
                    version: plugin.version.toString(),
                    cve: cve,
                    severity: severity,
                    cvss: cvssScore,
                    description: warning.message,
                    url: warning.url,
                    installed: plugin.version.toString()
                ]
                
                echo "   ❌ ${cve} - ${severity}"
            }
        }
    }
    
    vulnerabilities = vulnerabilities.unique { [it.plugin, it.cve] }
    
    env.VULNERABILITIES = groovy.json.JsonOutput.toJson(vulnerabilities)
    env.VULN_COUNT = vulnerabilities.size().toString()
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if (vulnerabilities.size() > 0) {
        currentBuild.result = 'UNSTABLE'
        echo "⚠️ Found ${vulnerabilities.size()} vulnerable plugins!"
        
        vulnerabilities.each { vuln ->
            echo "  ❌ ${vuln.plugin} ${vuln.version}: ${vuln.cve} (${vuln.severity})"
        }
    } else {
        echo "✅ No vulnerabilities detected"
        echo ""
        echo "💡 If Jenkins UI shows a vulnerability but this doesn't:"
        echo "   1. Check the console output above for 'HAS WARNINGS'"
        echo "   2. The plugin name might be different"
        echo "   3. Update Center might need manual refresh"
        echo "   4. Go to: Manage Jenkins → Manage Plugins → Advanced → Check now"
    }
}

@NonCPS
def determineSeverity(String message) {
    if (!message) return 'MEDIUM'
    
    def lowerMsg = message.toLowerCase()
    
    if (lowerMsg.contains('critical')) return 'CRITICAL'
    if (lowerMsg.contains('high')) return 'HIGH'
    if (lowerMsg.contains('low')) return 'LOW'
    
    return 'MEDIUM'
}

@NonCPS
def getCvssScore(String severity) {
    switch(severity) {
        case 'CRITICAL': return 9.0
        case 'HIGH': return 7.5
        case 'MEDIUM': return 5.0
        case 'LOW': return 3.0
        default: return 5.0
    }
}
