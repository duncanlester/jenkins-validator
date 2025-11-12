#!/usr/bin/env groovy

def fetchInstalledPlugins() {
    echo "📦 Fetching installed Jenkins plugins with enhanced metadata..."
    
    def pluginData = getPluginData()
    
    env.PLUGIN_DATA = groovy.json.JsonOutput.toJson(pluginData)
    
    writeFile file: 'plugins.json', text: env.PLUGIN_DATA
    archiveArtifacts artifacts: 'plugins.json'
    
    echo "✅ Found ${pluginData.size()} plugins with enhanced metadata"
}

@NonCPS
def getPluginData() {
    def jenkins = Jenkins.instance
    def pluginManager = jenkins.pluginManager
    def updateCenter = jenkins.updateCenter
    def plugins = pluginManager.plugins
    
    return plugins.collect { plugin ->
        def pluginInfo = updateCenter.getPlugin(plugin.shortName)
        def wrapper = plugin.wrapper
        
        // Extract additional metadata
        def metadata = [
            shortName: plugin.shortName,
            longName: plugin.longName,
            version: plugin.version.toString(),
            enabled: plugin.enabled,
            active: plugin.active,
            hasUpdate: plugin.hasUpdate(),
            pinned: plugin.pinned,
            deleted: plugin.deleted,
            downgradable: plugin.downgradable,
            
            // URLs and references
            url: plugin.url,
            scmUrl: pluginInfo?.scm?.toString() ?: null,
            issueTrackerUrl: pluginInfo?.issueTrackerUrl?.toString() ?: null,
            wikiUrl: pluginInfo?.wiki?.toString() ?: null,
            
            // Maintainers and developers
            developers: pluginInfo?.developers?.collect { dev ->
                [
                    name: dev.name ?: 'Unknown',
                    email: dev.email ?: null,
                    id: dev.developerId ?: null
                ]
            } ?: [],
            
            // Release information
            releaseTimestamp: pluginInfo?.releaseTimestamp?.toString() ?: null,
            buildDate: plugin.manifest?.mainAttributes?.getValue('Build-Date') ?: null,
            
            // Dependencies
            dependencies: plugin.dependencies.collect { dep ->
                [
                    shortName: dep.shortName,
                    version: dep.version.toString(),
                    optional: dep.optional
                ]
            },
            
            // Technical details
            bundled: plugin.bundled,
            supportsDynamicLoad: plugin.supportsDynamicLoad.toString(),
            requiredCoreVersion: pluginInfo?.requiredCore?.toString() ?: plugin.requiredCoreVersion?.toString() ?: 'Unknown',
            
            // File information
            archive: wrapper?.archive?.toString() ?: null,
            
            // Categories/Labels
            labels: pluginInfo?.labels?.collect { it.toString() } ?: [],
            
            // Popularity metrics (if available)
            popularity: pluginInfo?.popularity ?: null,
            installCount: pluginInfo?.popularity?.toString() ?: null,
            
            // License
            license: pluginInfo?.license?.name?.toString() ?: 'Unknown',
            licenseUrl: pluginInfo?.license?.url?.toString() ?: null,
            
            // Description
            excerpt: pluginInfo?.excerpt?.toString() ?: null,
        ]
        
        return metadata
    }
}

def fetchSecurityWarnings() {
    echo "🔍 Fetching security warnings from Jenkins..."
    
    def allWarnings = getSecurityWarnings()
    
    env.SECURITY_WARNINGS = groovy.json.JsonOutput.toJson(allWarnings)
    echo "⚠️ Found ${allWarnings.size()} security warnings"
}

@NonCPS
def getSecurityWarnings() {
    def jenkins = Jenkins.instance
    def pluginManager = jenkins.pluginManager
    def updateCenter = jenkins.updateCenter
    def allWarnings = []
    
    echo "🔍 Checking each installed plugin for security warnings..."
    
    pluginManager.plugins.each { plugin ->
        try {
            def pluginEntry = updateCenter.getPlugin(plugin.shortName)
            
            if (pluginEntry != null) {
                if (pluginEntry.hasWarnings()) {
                    echo "⚠️ ${plugin.shortName} ${plugin.version} HAS WARNINGS"
                    
                    def warnings = pluginEntry.getWarnings()
                    
                    if (warnings != null && !warnings.isEmpty()) {
                        warnings.each { warning ->
                            echo "   ID: ${warning.id} - ${warning.message?.take(50)}"
                            
                            allWarnings.add([
                                type: warning.type?.toString() ?: 'PLUGIN',
                                id: warning.id?.toString() ?: 'UNKNOWN',
                                name: plugin.shortName,
                                message: warning.message?.toString() ?: 'Security vulnerability',
                                url: warning.url?.toString() ?: '',
                                active: true,
                                versions: []
                            ])
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Skip plugins that can't be checked
        }
    }
    
    echo "📊 Collected ${allWarnings.size()} warnings"
    
    return allWarnings
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
    
    echo "📋 Checking ${pluginData.size()} plugins against ${securityWarnings.size()} security warnings"
    
    pluginData.each { plugin ->
        def matchingWarnings = securityWarnings.findAll { w -> w.name == plugin.shortName }
        
        if (matchingWarnings.size() > 0) {
            echo "⚠️ Found ${matchingWarnings.size()} warning(s) for ${plugin.shortName} ${plugin.version}"
            
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
                
                echo "   ❌ ${cve} (${severity})"
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
            echo "  ❌ ${vuln.plugin} ${vuln.version}: ${vuln.cve} (${vuln.severity})"
        }
    } else {
        echo "✅ No vulnerabilities detected"
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
