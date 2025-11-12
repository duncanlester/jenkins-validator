#!/usr/bin/env groovy

def fetchInstalledPlugins() {
    echo "📦 Fetching ALL plugin metadata..."
    def pluginData = getPluginData()
    env.PLUGIN_DATA = groovy.json.JsonOutput.toJson(pluginData)
    writeFile file: 'plugins.json', text: env.PLUGIN_DATA
    archiveArtifacts artifacts: 'plugins.json'
    echo "✅ Found ${pluginData.size()} plugins"
}

@NonCPS
def getPluginData() {
    def jenkins = Jenkins.instance
    def plugins = jenkins.pluginManager.plugins
    def updateCenter = jenkins.updateCenter
    
    return plugins.collect { p ->
        def m = [
            shortName: p.shortName,
            longName: p.longName,
            version: p.version.toString(),
            enabled: p.enabled,
            active: p.active,
            hasUpdate: p.hasUpdate(),
            url: p.url
        ]
        
        try { m.bundled = p.isBundled() } catch (e) { m.bundled = false }
        try { m.pinned = p.isPinned() } catch (e) { m.pinned = false }
        
        m.dependencies = p.dependencies.collect { d -> [shortName: d.shortName, version: d.version.toString(), optional: d.optional] }
        m.dependencyCount = m.dependencies.size()
        
        // Manifest
        try {
            def a = p.manifest?.mainAttributes
            if (a) {
                m.buildDate = a.getValue('Build-Date')
                m.builtBy = a.getValue('Built-By')
                m.jenkinsVersion = a.getValue('Jenkins-Version')
                m.pluginDevelopers = a.getValue('Plugin-Developers')
            }
        } catch (e) {}
        
        // UpdateCenter
        try {
            def pi = updateCenter.getPlugin(p.shortName)
            if (pi) {
                try { m.scm = pi.scm } catch (e) {}
                try { m.wiki = pi.wiki } catch (e) {}
                try { m.issueTrackerUrl = pi.issueTrackerUrl } catch (e) {}
                try { m.excerpt = pi.excerpt } catch (e) {}
                try { m.requiredCore = pi.requiredCore } catch (e) {}
                
                try {
                    def devs = pi.getDevelopers()
                    if (devs) {
                        m.developers = devs.collect { [name: it.name ?: 'Unknown', email: it.email, id: it.developerId] }
                        m.developerNames = m.developers.collect { it.name }.join(', ')
                    }
                } catch (e) {}
                
                try {
                    def cats = pi.getCategories()
                    if (cats) {
                        m.categories = cats.collect { it.toString() }
                        m.categoryNames = m.categories.join(', ')
                    }
                } catch (e) {}
            }
        } catch (e) {}
        
        if (!m.developerNames) m.developerNames = 'Unknown'
        if (!m.categoryNames) m.categoryNames = ''
        
        return m
    }
}

def fetchSecurityWarnings() {
    echo "🔍 Fetching security warnings..."
    def allWarnings = getSecurityWarnings()
    env.SECURITY_WARNINGS = groovy.json.JsonOutput.toJson(allWarnings)
    echo "⚠️ Found ${allWarnings.size()} warnings"
}

@NonCPS
def getSecurityWarnings() {
    def jenkins = Jenkins.instance
    def plugins = jenkins.pluginManager.plugins
    def updateCenter = jenkins.updateCenter
    def warnings = []
    
    plugins.each { p ->
        try {
            def pi = updateCenter.getPlugin(p.shortName)
            if (pi && pi.hasWarnings()) {
                pi.getWarnings().each { w ->
                    warnings.add([
                        type: w.type?.toString() ?: 'PLUGIN',
                        id: w.id?.toString() ?: 'UNKNOWN',
                        name: p.shortName,
                        message: w.message?.toString() ?: 'Security vulnerability',
                        url: w.url?.toString() ?: ''
                    ])
                }
            }
        } catch (e) {}
    }
    return warnings
}

def checkForUpdates() {
    def pluginData = readJSON text: env.PLUGIN_DATA
    def outdated = pluginData.findAll { it.hasUpdate }
    env.OUTDATED_COUNT = outdated.size().toString()
    env.OUTDATED_PLUGINS = groovy.json.JsonOutput.toJson(outdated)
}

def scanVulnerabilities() {
    def plugins = readJSON text: env.PLUGIN_DATA
    def warnings = readJSON text: env.SECURITY_WARNINGS
    def vulns = []
    
    plugins.each { p ->
        warnings.findAll { w -> w.name == p.shortName }.each { w ->
            def cve = (w.id =~ /CVE-\d{4}-\d+/) ? (w.id =~ /CVE-\d{4}-\d+/)[0] : w.id
            def sev = determineSeverity(w.message)
            vulns << [plugin: p.shortName, version: p.version, cve: cve, severity: sev, cvss: getCvssScore(sev), description: w.message, url: w.url, installed: p.version]
        }
    }
    
    vulns = vulns.unique { [it.plugin, it.cve] }
    env.VULNERABILITIES = groovy.json.JsonOutput.toJson(vulns)
    env.VULN_COUNT = vulns.size().toString()
    
    if (vulns.size() > 0) {
        currentBuild.result = 'UNSTABLE'
        echo "⚠️ Found ${vulns.size()} vulnerabilities"
    }
}

@NonCPS
def determineSeverity(String msg) {
    if (!msg) return 'MEDIUM'
    def m = msg.toLowerCase()
    if (m.contains('critical')) return 'CRITICAL'
    if (m.contains('high')) return 'HIGH'
    if (m.contains('low')) return 'LOW'
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
