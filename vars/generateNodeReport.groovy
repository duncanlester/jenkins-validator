import groovy.json.JsonSlurper

@NonCPS
def parseVulns(raw) {
    if (!raw?.trim()) return []
    def vulns = new JsonSlurper().parseText(raw)
    if (!(vulns instanceof List)) {
        if (vulns?.vulnerabilities instanceof List) {
            vulns = vulns.vulnerabilities
        } else if (vulns) {
            vulns = [vulns]
        } else {
            vulns = []
        }
    }
    return vulns.collect { v ->  // Return only primitive fields you need for report
        [
            affects: v.affects,
            component: v.component,
            package: v.package,
            pkg: v.pkg,
            plugin: v.plugin,
            name: v.name,
            version: v.version,
            id: v.id,
            cve: v.cve,
            severity: v.severity,
            ratings: v.ratings,
            description: v.description,
            summary: v.summary,
            url: v.url,
            source: v.source
        ]
    }
}

@NonCPS
def parsePackages(raw) {
    if (!raw?.trim()) return []
    def sbom = new JsonSlurper().parseText(raw)
    return sbom.components ?: []
}

def esc = { s ->
    if (s == null) return ''
    s = s.toString()
    s.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;')
}

def call(Map config = [:]) {
    String vulnJsonFile = config.get('vulnJsonFile') ?: 'dt-vulnerabilities.json'
    String reportFile = config.get('reportFile') ?: 'vulnerability-report.html'
    String sbomFile = config.get('sbomFile') ?: 'sbom.json'
    String projectName = config.get('projectName') ?: env.PROJECT_NAME ?: env.JOB_NAME ?: 'node-project'
    String projectVersion = config.get('projectVersion') ?: env.BUILD_NUMBER ?: '1.0.0'
    boolean publish = (config.get('publish') != null) ? config.get('publish') : true

    echo "generateNodeReport: vulnJsonFile=${vulnJsonFile} reportFile=${reportFile}"

    // Load CSS from library resource if available, otherwise fallback.
    def cssContent = ''
    try {
        cssContent = libraryResource('report-style.css')
    } catch (Exception e) {
        // Fallback minimal CSS
        cssContent = 'body { font-family: Arial, Helvetica, ... }'
    }
    writeFile file: 'report-style.css', text: cssContent

    // Parse vulnerabilities and packages up front, with helpers
    def vulns = []
    try {
        def raw = readFile(file: vulnJsonFile)
        vulns = parseVulns(raw)
    } catch (err) {
        echo "Warning: failed to parse ${vulnJsonFile} - ${err.message}"
        vulns = []
    }
    def vulnCount = vulns.size()
    def summaryColorClass = vulnCount > 0 ? "color-danger" : "color-success"

    def allPackages = []
    try {
        def sbomContent = readFile(file: sbomFile)
        allPackages = parsePackages(sbomContent)
    } catch (err) {
        echo "Warning: failed to parse SBOM - ${err.message}"
        allPackages = []
    }
    def packageCount = allPackages.size()

    // Build HTML report as before...
    def html = new StringBuilder()
    // ... (your big HTML-building block goes here, unchanged)

    writeFile file: reportFile, text: html.toString(), encoding: 'UTF-8'
    echo "Wrote ${reportFile} (size: ${new File(reportFile).length()} bytes)"

    if (publish) {
        publishHTML([reportDir: '.', reportFiles: reportFile, reportName: 'Node Vulnerability Report', keepAll: true, alwaysLinkToLastBuild: true, allowMissing: false])
    }
    archiveArtifacts artifacts: "${sbomFile}, ${vulnJsonFile}, ${reportFile}, report-style.css", allowEmptyArchive: true

    return reportFile
}
