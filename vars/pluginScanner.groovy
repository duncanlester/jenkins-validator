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
        try {
            def pluginInfo = updateCenter.getPlugin(plugin.shortName)
            
            // Extract metadata with completely safe property access
            def metadata = [
                // Basic information - always available
                shortName: plugin.shortName,
                longName: plugin.longName,
                version: plugin.version.toString(),
                enabled: plugin.enabled,
                active: plugin.active,
                hasUpdate: plugin.hasUpdate(),
                
                // Status flags - safe access
                pinned: getSafeProperty(plugin, 'pinned'),
                deleted: getSafeProperty(plugin, 'deleted'),
                downgradable: getSafeProperty(plugin, 'downgradable'),
                bundled: getSafeProperty(plugin, 'bundled'),
                
                // URLs - from PluginWrapper
                url: plugin.url,
                
                // URLs - from UpdateCenter (safe access)
                scmUrl: getSafeUpdateCenterProperty(pluginInfo, 'scm'),
                issueTrackerUrl: getSafeUpdateCenterProperty(pluginInfo, 'issueTrackerUrl'),
                wikiUrl: getSafeUpdateCenterProperty(pluginInfo, 'wiki'),
                
                // Maintainers and developers - safe access
                developers: getSafeDevelopers(pluginInfo),
                
                // Release information
                releaseTimestamp: getSafeUpdateCenterProperty(pluginInfo, 'releaseTimestamp'),
                buildDate: getSafeManifestAttribute(plugin, 'Build-Date'),
                
                // Dependencies - always available
                dependencies: plugin.dependencies.collect { dep ->
                    [
                        shortName: dep.shortName,
                        version: dep.version.toString(),
                        optional: dep.optional
                    ]
                },
                
                // Technical details
                requiredCoreVersion: getSafeUpdateCenterProperty(pluginInfo, 'requiredCore') ?: 
                                   plugin.requiredCoreVersion?.toString() ?: 
                                   'Unknown',
                
                // Categories/Labels - safe access
                labels: getSafeLabels(pluginInfo),
                
                // Popularity metrics
                popularity: getSafeUpdateCenterProperty(pluginInfo, 'popularity'),
                
                // License - safe access
                license: getSafeLicense(pluginInfo),
                licenseUrl: getSafeLicenseUrl(pluginInfo),
                
                // Description
                excerpt: getSafeUpdateCenterProperty(pluginInfo, 'excerpt'),
            ]
            
            return metadata
        } catch (Exception e) {
            // If any error occurs, return minimal metadata
            echo "⚠️ Error getting metadata for ${plugin.shortName}: ${e.message}"
            return [
                shortName: plugin.shortName,
                longName: plugin.longName,
                version: plugin.version.toString(),
                enabled: plugin.enabled,
                active: plugin.active,
                hasUpdate: false,
                developers: [],
                dependencies: [],
                labels: []
            ]
        }
    }
}

@NonCPS
private Object getSafeProperty(object, String propertyName) {
    try {
        if (object == null) return null
        def metaProperty = object.metaClass.getMetaProperty(propertyName)
        if (metaProperty != null) {
            return metaProperty.getProperty(object)
        }
        return null
    } catch (Exception e) {
        return null
    }
}

@NonCPS
private Object getSafeUpdateCenterProperty(pluginInfo, String propertyName) {
    try {
        if (pluginInfo == null) return null
        def metaProperty = pluginInfo.metaClass.getMetaProperty(propertyName)
        if (metaProperty != null) {
            def value = metaProperty.getProperty(pluginInfo)
            return value?.toString()
        }
        return null
    } catch (Exception e) {
        return null
    }
}

@NonCPS
private String getSafeManifestAttribute(plugin, String attributeName) {
    try {
        return plugin.manifest?.mainAttributes?.getValue(attributeName) ?: null
    } catch (Exception e) {
        return null
    }
}

@NonCPS
private List getSafeDevelopers(pluginInfo) {
    try {
        if (pluginInfo == null) return []
        
        def devProperty = pluginInfo.metaClass.getMetaProperty('developers')
        if (devProperty == null) return []
        
        def developers = devProperty.getProperty(pluginInfo)
        if (developers == null || developers.isEmpty()) return []
        
        return developers.collect { dev ->
            [
                name: dev.name ?: 'Unknown',
                email: dev.email ?: null,
                id: dev.developerId ?: null
            ]
        }
    } catch (Exception e) {
        return []
    }
}

@NonCPS
private List getSafeLabels(pluginInfo) {
    try {
        if (pluginInfo == null) return []
        
        def labelProperty = pluginInfo.metaClass.getMetaProperty('labels')
        if (labelProperty == null) return []
        
        def labels = labelProperty.getProperty(pluginInfo)
        if (labels == null) return []
        
        return labels.collect { it.toString() }
    } catch (Exception e) {
        return []
    }
}

@NonCPS
private String getSafeLicense(pluginInfo) {
    try {
        if (pluginInfo == null) return 'Unknown'
        
        def licenseProperty = pluginInfo.metaClass.getMetaProperty('license')
        if (licenseProperty == null) return 'Unknown'
        
        def license = licenseProperty.getProperty(pluginInfo)
        if (license == null) return 'Unknown'
        
        // License might have a name property
        def nameProperty = license.metaClass.getMetaProperty('name')
        if (nameProperty != null) {
            return nameProperty.getProperty(license)?.toString() ?: 'Unknown'
        }
        
        return license.toString()
    } catch (Exception e) {
        return 'Unknown'
    }
}

@NonCPS
private String getSafeLicenseUrl(pluginInfo) {
    try {
        if (pluginInfo == null) return null
        
        def licenseProperty = pluginInfo.metaClass.getMetaProperty('license')
        if (licenseProperty == null) return null
        
        def license = licenseProperty.getProperty(pluginInfo)
        if (license == null) return null
        
        // License might have a url property
        def urlProperty = license.metaClass.getMetaProperty('url')
        if (urlProperty != null) {
            return urlProperty.getProperty(license)?.toString()
        }
        
        return null
    } catch (Exception e) {
        return null
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
