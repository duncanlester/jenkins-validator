import groovy.json.JsonSlurper

@NonCPS
def parseVulns(raw) {
    if (!raw?.trim()) return []
    def vulns
    try {
        vulns = new JsonSlurper().parseText(raw)
    } catch (Exception e) {
        return []
    }
    // Defensive: handle object or array response
    if (!(vulns instanceof List)) {
        if (vulns?.vulnerabilities instanceof List) {
            vulns = vulns.vulnerabilities
        } else if (vulns) {
            vulns = [vulns]
        } else {
            vulns = []
        }
    }

    // Return only scalars (string/int) in the maps -- never full objects/lists!
    vulns.collect { v ->
        def affectedName = (
            v?.affects instanceof List && v.affects.size() > 0 && v.affects[0]?.ref ?
                (v.affects[0].ref.toString().contains('@')
                    ? v.affects[0].ref.toString().split('@')[0]
                    : v.affects[0].ref.toString())
                : (v.component ?: v.package ?: v.pkg ?: v.plugin ?: v.name ?: 'unknown')
        )
        def affectedVersion = (
            v?.affects instanceof List && v.affects.size() > 0 && v.affects[0]?.ref && v.affects[0].ref.toString().contains('@')
                ? v.affects[0].ref.toString().split('@')[-1]
                : (v.version ?: '')
        )
        def severity = (
            v?.ratings instanceof List && v.ratings.size() > 0 && v.ratings[0]?.severity
                ? v.ratings[0].severity.toString().toUpperCase()
                : (v.severity ?: '').toString().toUpperCase()
        )
        def score = (
            v?.ratings instanceof List && v.ratings.size() > 0 && v.ratings[0]?.score
                ? v.ratings[0].score.toString()
                : ''
        )
        def id = (v.id ?: v.cve ?: v.name ?: 'N/A').toString()
        def desc = (v.description ?: v.summary ?: '').toString()
        def link = ''
        if (v?.source?.url) {
            def sourceUrl = v.source.url.toString()
            def sourceName = (v.source.name ?: 'source').toString()
            link = "<a href='${escapeHtml(sourceUrl)}' target='_blank'>${escapeHtml(sourceName)}</a>"
        } else if (v?.url) {
            link = "<a href='${escapeHtml(v.url.toString())}' target='_blank'>advisory</a>"
        }
        [
            affectedName: affectedName,
            affectedVersion: affectedVersion,
            id: id,
            severity: severity,
            score: score,
            desc: desc,
            link: link
        ]
    }
}

@NonCPS
def parsePackages(raw) {
    if (!raw?.trim()) return []
    def sbom
    try {
        sbom = new JsonSlurper().parseText(raw)
    } catch (Exception e) {
        return []
    }
    if (!sbom?.components) {
        return []
    }
    // Only take flat primitives
    sbom.components.collect { c ->
        [
            name: c.name?.toString(),
            version: (c.version ?: '')?.toString(),
            type: (c.type ?: '')?.toString(),
            purl: (c.purl ?: '')?.toString()
        ]
    }
}

def escapeHtml(s) {
    if (s == null) return ''
    s = s.toString()
    s.replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;')
}

def call(Map config = [:]) {
    String vulnJsonFile = config.get('vulnJsonFile') ?: 'dt-vulnerabilities.json'
    String reportFile = config.get('reportFile') ?: 'vulnerability-report.html'
    String sbomFile = config.get('sbomFile') ?: 'sbom.json'
    String projectName = config.get('projectName') ?: env.PROJECT_NAME ?: env.JOB_NAME ?: 'node-project'
    String projectVersion = config.get('projectVersion') ?: env.BUILD_NUMBER ?: '1.0.0'
    boolean publish = (config.get('publish') != null) ? config.get('publish') : true

    echo "node_renderNodeReport: input=${vulnJsonFile} output=${reportFile}"

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

    def html = new StringBuilder()
    html << "<!DOCTYPE html>\n"
    html << "<html lang=\"en\">\n<head>\n"
    html << "  <meta charset=\"UTF-8\">\n"
    html << "  <title>Node.js Vulnerability Report</title>\n"
    html << "</head>\n<body>\n"
    html << "  <div class=\"container\">\n"
    html << "    <h1>Node.js Vulnerability Report</h1>\n"
    html << "    <div><strong>Project:</strong> ${escapeHtml(projectName)}</div>\n"
    html << "    <div><strong>Version:</strong> ${escapeHtml(projectVersion)}</div>\n"
    html << "    <div><strong>Generated:</strong> ${new Date().toString()}</div>\n"
    html << "    <h2>Vulnerability Summary</h2>\n"
    html << "    <div>Total Packages: ${packageCount}</div>\n"
    html << "    <div class='${summaryColorClass}'>Vulnerabilities: ${vulnCount} found</div>\n"

    if (vulnCount == 0) {
        html << "<div>No vulnerabilities detected. All packages are secure.</div>\n"
    } else {
        html << "<h2>Vulnerabilities (${vulnCount} found)</h2>\n"
        html << "<table><thead><tr>"
        html << "<th>#</th><th>Package</th><th>Version</th><th>ID</th><th>Severity</th><th>Score</th><th>Description</th><th>Link</th></tr></thead><tbody>\n"
        for (int i = 0; i < vulns.size(); i++) {
            def v = vulns[i]
            html << "<tr class='${escapeHtml(v.severity)}'>"
            html << "<td>${i + 1}</td>"
            html << "<td>${escapeHtml(v.affectedName)}</td>"
            html << "<td>${escapeHtml(v.affectedVersion)}</td>"
            html << "<td><pre class='small'>${escapeHtml(v.id.toString())}</pre></td>"
            html << "<td>${escapeHtml(v.severity)}</td>"
            html << "<td>${escapeHtml(v.score.toString())}</td>"
            html << "<td><pre>${escapeHtml(v.desc)}</pre></td>"
            html << "<td>${v.link}</td>"
            html << "</tr>\n"
        }
        html << "</tbody></table>\n"
    }

    if (packageCount > 0) {
        html << "<h2>All Packages (${packageCount} total)</h2>\n"
        html << "<table><thead><tr><th>Package</th><th>Version</th><th>Type</th><th>purl</th></tr></thead><tbody>\n"
        int shown = 0
        allPackages.each { c ->
            if (shown++ < 100) {
                html << "<tr>"
                html << "<td>${escapeHtml(c.name)}</td>"
                html << "<td>${escapeHtml(c.version)}</td>"
                html << "<td>${escapeHtml(c.type)}</td>"
                html << "<td><code>${escapeHtml(c.purl)}</code></td>"
                html << "</tr>\n"
            }
        }
        if (shown == 100 && packageCount > 100) {
            html << "<tr><td colspan='4'><em>More packages not shown...</em></td></tr>"
        }
        html << "</tbody></table>\n"
    }

    html << "  </div>\n</body>\n</html>\n"

    writeFile file: reportFile, text: html.toString(), encoding: 'UTF-8'
    echo "Wrote ${reportFile} (size: ${new File(reportFile).length()} bytes)"

    if (publish) {
        publishHTML([reportDir: '.', reportFiles: reportFile, reportName: 'Node Vulnerability Report', keepAll: true, alwaysLinkToLastBuild: true, allowMissing: false])
    }
    archiveArtifacts artifacts: "${sbomFile}, ${vulnJsonFile}, ${reportFile}", allowEmptyArchive: true

    return reportFile
}
