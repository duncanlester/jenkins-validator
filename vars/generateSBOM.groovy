#!/usr/bin/env groovy

def call() {
    echo "📦 Generating Software Bill of Materials (SBOM)..."
    
    def plugins = readJSON text: env.PLUGIN_DATA
    def vulns = readJSON text: (env.VULNERABILITIES ?: '[]')
    
    def timestamp = new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'", TimeZone.getTimeZone('UTC'))
    def jenkinsVersion = Jenkins.instance.version.toString()
    
    echo "Building SBOM with ${plugins.size()} components and ${vulns.size()} vulnerabilities"
    
    def sbom = buildSBOM(plugins, vulns, timestamp, jenkinsVersion)
    
    def sbomJson = groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(sbom))
    writeFile file: 'sbom.json', text: sbomJson
    
    echo "✅ CycloneDX SBOM: ${sbom.components.size()} components, ${sbom.vulnerabilities.size()} vulnerabilities"
    
    def spdxContent = generateSPDX(plugins, jenkinsVersion, timestamp)
    echo "✅ SPDX SBOM: ${plugins.size()} packages"
    
    generateSBOMReport(sbom, spdxContent, plugins.size(), vulns.size())
    
    archiveArtifacts artifacts: 'sbom.json,sbom.spdx,sbom-report.html,sbom-style.css'
    
    echo "✅ SBOM generated: ${plugins.size()} components, ${vulns.size()} vulnerabilities"
}

@NonCPS
def buildSBOM(plugins, vulns, timestamp, jenkinsVersion) {
    def sbom = [:]
    sbom.bomFormat = "CycloneDX"
    sbom.specVersion = "1.5"
    sbom.serialNumber = "urn:uuid:${UUID.randomUUID()}"
    sbom.version = 1
    sbom.metadata = [:]
    sbom.metadata.timestamp = timestamp
    sbom.metadata.tools = []
    
    def tool = [:]
    tool.vendor = "Jenkins"
    tool.name = "plugin-validator"
    tool.version = "1.0.0"
    sbom.metadata.tools << tool
    
    sbom.metadata.component = [:]
    sbom.metadata.component.type = "application"
    sbom.metadata.component.name = "Jenkins"
    sbom.metadata.component.version = jenkinsVersion
    sbom.metadata.component.description = "Jenkins Automation Server"
    
    sbom.components = []
    sbom.vulnerabilities = []
    
    plugins.each { p ->
        def component = [:]
        component.type = "library"
        component.name = p.shortName
        component.version = p.version
        component.description = p.longName
        component.purl = "pkg:jenkins/plugin/${p.shortName}@${p.version}"
        component.properties = []
        
        def enabledProp = [:]
        enabledProp.name = "enabled"
        enabledProp.value = p.enabled.toString()
        component.properties << enabledProp
        
        def bundledProp = [:]
        bundledProp.name = "bundled"
        bundledProp.value = (p.bundled ?: false).toString()
        component.properties << bundledProp
        
        if (p.url) {
            component.externalReferences = []
            def ref = [:]
            ref.type = "website"
            ref.url = p.url
            component.externalReferences << ref
        }
        
        sbom.components << component
    }
    
    vulns.each { v ->
        def vuln = [:]
        vuln.id = v.cve
        vuln.source = [:]
        vuln.source.name = "Jenkins Security Advisory"
        vuln.source.url = v.url ?: "https://www.jenkins.io/security/advisories/"
        
        vuln.ratings = []
        def rating = [:]
        rating.severity = v.severity
        rating.score = v.cvss
        rating.method = "CVSSv3"
        vuln.ratings << rating
        
        vuln.description = v.description
        
        vuln.affects = []
        def affect = [:]
        affect.ref = "pkg:jenkins/plugin/${v.plugin}@${v.version}"
        vuln.affects << affect
        
        sbom.vulnerabilities << vuln
    }
    
    return sbom
}

def generateSPDX(plugins, jenkinsVersion, timestamp) {
    def spdx = buildSPDXContent(plugins, jenkinsVersion)
    writeFile file: 'sbom.spdx', text: spdx
    return spdx
}

@NonCPS
def buildSPDXContent(plugins, jenkinsVersion) {
    def spdx = new StringBuilder()
    def docId = UUID.randomUUID().toString()
    
    spdx << "SPDXVersion: SPDX-2.3\n"
    spdx << "DataLicense: CC0-1.0\n"
    spdx << "SPDXID: SPDDocument\n"
    spdx << "DocumentName: Jenkins-Plugin-SBOM\n"
    spdx << "DocumentNamespace: https://jenkins.io/sbom/${docId}\n"
    spdx << "Creator: Tool: plugin-validator-1.0.0\n"
    spdx << "\n"
    spdx << "PackageName: Jenkins\n"
    spdx << "SPDXID: SPDPackage-Jenkins\n"
    spdx << "PackageVersion: ${jenkinsVersion}\n"
    spdx << "PackageDownloadLocation: https://www.jenkins.io/\n"
    spdx << "FilesAnalyzed: false\n"
    spdx << "\n"
    
    plugins.each { p ->
        def pkgId = "SPDPackage-${p.shortName.replaceAll('[^a-zA-Z0-9]', '-')}"
        spdx << "PackageName: ${p.shortName}\n"
        spdx << "SPDXID: ${pkgId}\n"
        spdx << "PackageVersion: ${p.version}\n"
        spdx << "PackageDownloadLocation: ${p.url ?: 'NOASSERTION'}\n"
        spdx << "FilesAnalyzed: false\n"
        spdx << "\n"
        spdx << "Relationship: SPDPackage-Jenkins DEPENDS_ON ${pkgId}\n"
        spdx << "\n"
    }
    
    return spdx.toString()
}

def generateSBOMReport(sbom, spdxContent, componentCount, vulnCount) {
    def cssContent = libraryResource('report-style.css')
    writeFile file: 'sbom-style.css', text: cssContent
    
    def serialNum = sbom.serialNumber.replaceAll('urn:uuid:', '')
    def vulnColorClass = vulnCount > 0 ? 'color-danger' : 'color-success'
    
    def spdxHtml = escapeHtml(spdxContent.toString())
    
    def html = buildReportHtml(sbom, spdxHtml, serialNum, vulnColorClass, componentCount, vulnCount)
    
    writeFile file: 'sbom-report.html', text: html
}

@NonCPS
def escapeHtml(str) {
    if (!str) return ''
    return str.toString()
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
}

@NonCPS
def buildReportHtml(sbom, spdxHtml, serialNum, vulnColorClass, componentCount, vulnCount) {
    def html = new StringBuilder()
    
    html << '<!DOCTYPE html>\n'
    html << '<html lang="en">\n'
    html << '<head>\n'
    html << '    <meta charset="UTF-8">\n'
    html << '    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
    html << '    <title>SBOM Report</title>\n'
    html << '    <link rel="stylesheet" href="sbom-style.css">\n'
    html << '</head>\n'
    html << '<body>\n'
    html << '    <div class="container">\n'
    html << '        <div class="header">\n'
    html << '            <h1>📦 Software Bill of Materials (SBOM)</h1>\n'
    html << '            <div class="header-meta">\n'
    html << "                <div><strong>Format:</strong> CycloneDX 1.5 / SPDX 2.3</div>\n"
    html << "                <div><strong>Generated:</strong> ${sbom.metadata.timestamp}</div>\n"
    html << "                <div><strong>Components:</strong> ${componentCount}</div>\n"
    html << '            </div>\n'
    html << '        </div>\n'
    html << '        \n'
    html << '        <div class="section">\n'
    html << '            <h2>📊 SBOM Summary</h2>\n'
    html << '            <div class="summary-grid">\n'
    html << '                <div class="summary-item">\n'
    html << '                    <h4>Total Components</h4>\n'
    html << "                    <div class=\"summary-value\">${componentCount}</div>\n"
    html << '                </div>\n'
    html << '                <div class="summary-item">\n'
    html << '                    <h4>Vulnerabilities</h4>\n'
    html << "                    <div class=\"summary-value ${vulnColorClass}\">${vulnCount}</div>\n"
    html << '                </div>\n'
    html << '                <div class="summary-item">\n'
    html << '                    <h4>SBOM Format</h4>\n'
    html << '                    <div class="summary-value">CycloneDX 1.5</div>\n'
    html << '                </div>\n'
    html << '                <div class="summary-item">\n'
    html << '                    <h4>Serial Number</h4>\n'
    html << "                    <div class=\"summary-value serial-number\">${serialNum}</div>\n"
    html << '                </div>\n'
    html << '            </div>\n'
    html << '            \n'
    html << '            <div class="links-group">\n'
    html << '                <a href="sbom.json" class="issue-link" download>📥 Download CycloneDX JSON</a>\n'
    html << '                <a href="sbom.spdx" class="issue-link" download>📥 Download SPDX</a>\n'
    html << '                <a href="plugins.json" class="issue-link" download>📥 Download Raw Data</a>\n'
    html << '            </div>\n'
    html << '        </div>\n'
    html << '        \n'
    
    if (vulnCount > 0) {
        html << '        <div class="section">\n'
        html << "            <h2>🚨 Vulnerabilities in SBOM (${vulnCount})</h2>\n"
        html << '            <p class="sbom-intro">CycloneDX format includes vulnerability data. The SBOM JSON contains:</p>\n'
        html << '            <ul class="sbom-list">\n'
        html << "                <li><strong>${componentCount} components</strong> - All Jenkins plugins installed</li>\n"
        html << "                <li><strong>${vulnCount} vulnerabilities</strong> - Security advisories mapped to components</li>\n"
        html << '                <li><strong>CVSS scores</strong> - Severity ratings for each vulnerability</li>\n'
        html << '                <li><strong>Package URLs (PURL)</strong> - Unique identifiers for each component</li>\n'
        html << '            </ul>\n'
        html << '            <p class="sbom-intro"><strong>Why CycloneDX?</strong> CycloneDX is specifically designed for security use cases.</p>\n'
        html << '        </div>\n'
    }
    
    html << '        <div class="section">\n'
    html << '            <h2>📋 SPDX Document (ISO/IEC 5962:2021)</h2>\n'
    html << '            <p class="sbom-intro">Software Package Data eXchange (SPDX) standard for SBOM.</p>\n'
    html << '            <pre class="spdx-viewer"><code>' + spdxHtml + '</code></pre>\n'
    html << '        </div>\n'
    html << '    </div>\n'
    html << '</body>\n'
    html << '</html>\n'
    
    return html.toString()
}
