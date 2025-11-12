#!/usr/bin/env groovy

def call() {
    echo "🛡️ Scanning for vulnerabilities..."
    
    def plugins = readJSON text: env.PLUGIN_DATA
    def warnings = readJSON text: (env.SECURITY_WARNINGS ?: '[]')
    
    echo "📊 Loaded ${plugins.size()} plugins"
    echo "📊 Loaded ${warnings.size()} security warnings"
    
    // Debug: Check if Build Pipeline Plugin is in the list
    def buildPipeline = plugins.find { it.shortName == 'build-pipeline-plugin' }
    if (buildPipeline) {
        echo "✅ Found build-pipeline-plugin version ${buildPipeline.version}"
    } else {
        echo "❌ build-pipeline-plugin NOT found in plugin list"
    }
    
    // Debug: Check if there's a warning for it
    def buildPipelineWarning = warnings.find { it.name == 'build-pipeline-plugin' }
    if (buildPipelineWarning) {
        echo "✅ Found security warning for build-pipeline-plugin"
        echo "   Warning: ${buildPipelineWarning}"
    } else {
        echo "❌ No security warning found for build-pipeline-plugin"
    }
    
    def vulnerabilities = findVulnerabilities(plugins, warnings)
    
    echo "🚨 Found ${vulnerabilities.size()} vulnerabilities"
    
    // Debug: List all vulnerabilities found
    vulnerabilities.each { v ->
        echo "   - ${v.plugin} ${v.version}: ${v.cve} (${v.severity})"
    }
    
    env.VULNERABILITIES = groovy.json.JsonOutput.toJson(vulnerabilities)
    env.VULN_COUNT = vulnerabilities.size().toString()
    
    if (vulnerabilities.size() > 0) {
        currentBuild.result = 'UNSTABLE'
    }
    
    return vulnerabilities
}

@NonCPS
def findVulnerabilities(plugins, warnings) {
    def vulnerabilities = []
    
    plugins.each { plugin ->
        warnings.each { warning ->
            // Try both exact match and with/without -plugin suffix
            def pluginMatches = (warning.name == plugin.shortName) || 
                                (warning.name == plugin.shortName + '-plugin') ||
                                (warning.name + '-plugin' == plugin.shortName)
            
            if (pluginMatches) {
                // Check if warning has versions array
                if (warning.versions && warning.versions.size() > 0) {
                    warning.versions.each { vulnVersion ->
                        // Check if plugin version is affected
                        def isAffected = false
                        
                        if (vulnVersion.lastVersion) {
                            // Plugin is affected if version <= lastVersion
                            if (compareVersions(plugin.version, vulnVersion.lastVersion) <= 0) {
                                isAffected = true
                            }
                        } else if (vulnVersion.firstVersion) {
                            // Plugin is affected if version >= firstVersion
                            if (compareVersions(plugin.version, vulnVersion.firstVersion) >= 0) {
                                isAffected = true
                            }
                        } else {
                            // No version specified, assume all versions affected
                            isAffected = true
                        }
                        
                        if (isAffected) {
                            vulnerabilities << [
                                plugin: plugin.shortName,
                                version: plugin.version,
                                cve: vulnVersion.pattern ?: 'SECURITY-ADVISORY',
                                severity: determineSeverity(vulnVersion),
                                description: warning.message ?: 'Security vulnerability detected',
                                url: warning.url ?: "https://www.jenkins.io/security/plugins/#${plugin.shortName}",
                                cvss: vulnVersion.cvss ?: 0.0
                            ]
                        }
                    }
                } else {
                    // No version info, treat as affecting all versions
                    vulnerabilities << [
                        plugin: plugin.shortName,
                        version: plugin.version,
                        cve: 'SECURITY-ADVISORY',
                        severity: 'HIGH',
                        description: warning.message ?: 'Security vulnerability detected',
                        url: warning.url ?: "https://www.jenkins.io/security/plugins/#${plugin.shortName}",
                        cvss: 5.0
                    ]
                }
            }
        }
    }
    
    return vulnerabilities
}

@NonCPS
def compareVersions(String v1, String v2) {
    if (!v1 || !v2) return 0
    
    def parts1 = v1.tokenize('.-_')
    def parts2 = v2.tokenize('.-_')
    
    def maxLen = Math.max(parts1.size(), parts2.size())
    
    for (int i = 0; i < maxLen; i++) {
        def p1 = i < parts1.size() ? parts1[i] : '0'
        def p2 = i < parts2.size() ? parts2[i] : '0'
        
        // Try to parse as integers
        try {
            def n1 = p1.replaceAll(/[^0-9]/, '')
            def n2 = p2.replaceAll(/[^0-9]/, '')
            
            if (n1 && n2) {
                def num1 = n1.toInteger()
                def num2 = n2.toInteger()
                
                if (num1 < num2) return -1
                if (num1 > num2) return 1
            }
        } catch (Exception e) {
            // If parsing fails, compare as strings
            if (p1 < p2) return -1
            if (p1 > p2) return 1
        }
    }
    
    return 0
}

@NonCPS
def determineSeverity(vulnVersion) {
    def cvss = vulnVersion.cvss ?: 0.0
    
    if (cvss >= 9.0) return 'CRITICAL'
    if (cvss >= 7.0) return 'HIGH'
    if (cvss >= 4.0) return 'MEDIUM'
    return 'LOW'
}
