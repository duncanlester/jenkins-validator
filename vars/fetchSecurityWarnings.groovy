#!/usr/bin/env groovy

def call() {
    echo "Fetching security warnings..."
    
    try {
        def warnings = getWarningsFromUpdateCenter()
        
        if (warnings && warnings.size() > 0) {
            echo "Fetched ${warnings.size()} warnings from Jenkins Update Center"
            def warningsJson = groovy.json.JsonOutput.toJson(warnings)
            writeFile file: 'security-warnings.json', text: warningsJson
            archiveArtifacts artifacts: 'security-warnings.json'
            env.SECURITY_WARNINGS = warningsJson
            
            echo "Sample warnings:"
            warnings.take(5).each { w ->
                echo "  - ${w.name}"
            }
            
            return
        }
        
    } catch (Exception e) {
        echo "Could not fetch from Update Center: ${e.message}"
    }
    
    // Fallback to hardcoded warnings
    echo "Using hardcoded vulnerability database..."
    def hardcodedWarnings = getHardcodedWarnings()
    def warningsJson = groovy.json.JsonOutput.toJson(hardcodedWarnings)
    writeFile file: 'security-warnings.json', text: warningsJson
    archiveArtifacts artifacts: 'security-warnings.json'
    env.SECURITY_WARNINGS = warningsJson
    echo "Loaded ${hardcodedWarnings.size()} hardcoded warnings"
}

@NonCPS
def getWarningsFromUpdateCenter() {
    try {
        def jenkins = Jenkins.instance
        def updateCenter = jenkins.getUpdateCenter()
        
        def warnings = []
        def sites = updateCenter.getSites()
        
        sites.each { site ->
            def data = site.getData()
            if (data && data.warnings) {
                data.warnings.each { warning ->
                    def warningMap = [:]
                    warningMap.id = warning.id ?: 'UNKNOWN'
                    warningMap.name = warning.name ?: ''
                    warningMap.message = warning.message ?: ''
                    warningMap.url = warning.url ?: ''
                    warningMap.type = warning.type ?: 'plugin'
                    warningMap.versions = []
                    
                    if (warning.versions) {
                        warning.versions.each { v ->
                            def versionMap = [:]
                            versionMap.firstVersion = v.firstVersion
                            versionMap.lastVersion = v.lastVersion
                            versionMap.pattern = v.pattern
                            warningMap.versions << versionMap
                        }
                    }
                    
                    warnings << warningMap
                }
            }
        }
        
        return warnings
        
    } catch (Exception e) {
        return []
    }
}

@NonCPS
def getHardcodedWarnings() {
    def warnings = []
    
    def warning1 = [:]
    warning1.id = 'SECURITY-2824'
    warning1.name = 'build-pipeline-plugin'
    warning1.message = 'Build Pipeline Plugin 2.0.2 and earlier does not escape the name and description of builds shown on the pipeline view, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers with Item/Configure permission.'
    warning1.url = 'https://www.jenkins.io/security/advisory/2023-07-26/#SECURITY-2824'
    warning1.type = 'plugin'
    warning1.versions = []
    
    def version1 = [:]
    version1.firstVersion = null
    version1.lastVersion = '2.0.2'
    version1.pattern = 'SECURITY-2824'
    warning1.versions << version1
    
    warnings << warning1
    
    def warning2 = [:]
    warning2.id = 'SECURITY-2825'
    warning2.name = 'build-pipeline-plugin'
    warning2.message = 'Build Pipeline Plugin 2.0.2 and earlier does not escape the name of jobs shown in the pipeline view, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers with Item/Configure permission.'
    warning2.url = 'https://www.jenkins.io/security/advisory/2023-07-26/#SECURITY-2825'
    warning2.type = 'plugin'
    warning2.versions = []
    
    def version2 = [:]
    version2.firstVersion = null
    version2.lastVersion = '2.0.2'
    version2.pattern = 'SECURITY-2825'
    warning2.versions << version2
    
    warnings << warning2
    
    return warnings
}
