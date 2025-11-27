// Generates a styled HTML Node.js vulnerability report with summary, all packages, and publishes/archives outputs.
// Use in pipeline: generateNodeReport(
//   vulnJsonFile: 'dt-vulnerabilities.json',
//   reportFile: 'vulnerability-report.html',
//   sbomFile: 'sbom.json',
//   projectName: 'My App',
//   projectVersion: '1.0.0',
//   publish: true
// )
import groovy.json.JsonSlurper

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
        cssContent = '''
        body { font-family: Arial, Helvetica, sans-serif; margin: 24px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; vertical-align: top; }
        th { background: #4682b4; color: #fff; }
        .color-danger { background:#ffcccc; color:#900; font-weight:bold }
        .color-success { background:#c6efce; color:#444 }
        .color-warning { background:#fff4cc; color:#665200 }
        .badge-enabled { background:#229944; color:#fff; padding:3px 6px; border-radius:4px; }
        .badge-disabled { background: #888; color:#fff; padding:3px 6px; border-radius:4px; }
        .container { max-width:1100px;margin:auto }
        .header-meta { margin-bottom:10px;font-size:1.05em }
        .section { margin-bottom:24px }
        .summary-grid { display:flex;gap:32px; }
        .summary-item { background:#f7f7f7;padding:12px 18px;border-radius:7px;box-shadow:0 1px 2px #eee; }
        .summary-value { font-size:2em;margin-top:6px }
        .summary-item-success { background:#e0ffe0;padding:18px 18px;border-radius:7px }
        '''
    }
    writeFile file: 'report-style.css', text: cssContent

    // Load vulnerabilities
    def vulns = []
    try {
        def raw = readFile(file: vulnJsonFile)
        if (raw?.trim()) {
            vulns = new JsonSlurper().parseText(raw)
            if (!(vulns instanceof List)) {
                if (vulns?.vulnerabilities instanceof List) {
                    vulns = vulns.vulnerabilities
                } else {
                    if (vulns) { vulns = [vulns] }
                }
            }
        }
    } catch (err) {
        echo "Warning: failed to parse ${vulnJsonFile} - ${err.message}"
        vulns = []
    }
    def vulnCount = vulns.size()
    def summaryColorClass = vulnCount > 0 ? "color-danger" : "color-success"

    // Load SBOM/package data
    def sbomJson = [:]
    def packageCount = 0
    def allPackages = []
    try {
        def sbomContent = readFile(file: sbomFile)
        sbomJson = new JsonSlurper().parseText(sbomContent)
        allPackages = sbomJson.components ?: []
        packageCount = allPackages.size()
    } catch (err) {
        echo "Warning: failed to parse SBOM - ${err.message}"
        packageCount = 0
        allPackages = []
    }

    def esc = { s ->
        if (s == null) return ''
        s = s.toString()
        s.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;')
    }

    def html = new StringBuilder()
    html << "<!DOCTYPE html>\n"
    html << "<html lang=\"en\">\n<head>\n"
    html << "  <meta charset=\"UTF-8\">\n"
    html << "  <title>Node.js Vulnerability Report</title>\n"
    html << "  <link rel=\"stylesheet\" href=\"report-style.css\">\n"
    html << "</head>\n<body>\n"
    html << "  <div class=\"container\">\n"
    html << "    <div class=\"header\">\n"
    html << "      <h1>🛡️ Node.js Vulnerability Report</h1>\n"
    html << "      <div class=\"header-meta\">\n"
    html << "        <div><strong>Project:</strong> ${esc(projectName)}</div>\n"
    html << "        <div><strong>Version:</strong> ${esc(projectVersion)}</div>\n"
    html << "        <div><strong>Generated:</strong> ${new Date().toString()}</div>\n"
    html << "      </div>\n"
    html << "    </div>\n"
    html << "    <div class=\"section\">\n"
    html << "      <h2>📊 Vulnerability Summary</h2>\n"
    html << "      <div class=\"summary-grid\">\n"
    html << "        <div class=\"summary-item\"><h4>Total Packages</h4><div class=\"summary-value\">${packageCount}</div></div>\n"
    html << "        <div class=\"summary-item\"><h4>Vulnerabilities</h4><div class=\"summary-value ${summaryColorClass}\">${vulnCount} found</div></div>\n"
    html << "      </div>\n"
    html << "    </div>\n"

    if (vulnCount == 0) {
        html << """
            <div class="section">
                <h2>✅ Security Status</h2>
                <div class="summary-item-success">
                    <h4>No Vulnerabilities Detected</h4>
                    <div class="summary-value color-success">All packages are secure</div>
                </div>
            </div>
        """
    } else {
        html << """
        <div class="section">
          <h2>🚨 Vulnerabilities (${vulnCount} found)</h2>
          <table>
            <thead>
              <tr>
                <th>#</th><th>Package</th><th>Version</th><th>ID</th><th>Severity</th><th>Score</th><th>Description</th><th>Link</th>
              </tr>
            </thead>
            <tbody>
        """
        for (int i = 0; i < vulns.size(); i++) {
            def v = vulns[i]
            def affectedName = 'unknown'
            def affectedVersion = ''
            try {
                if (v?.affects && v.affects.size() > 0 && v.affects[0].ref) {
                    def ref = v.affects[0].ref.toString()
                    def at = ref.lastIndexOf('@')
                    if (at > 0) {
                        affectedName = ref.substring(0, at)
                        affectedVersion = ref.substring(at + 1)
                    } else {
                        affectedName = ref
                    }
                } else {
                    affectedName = v.component ?: v.package ?: v.pkg ?: v.plugin ?: v.name ?: 'unknown'
                    affectedVersion = v.version ?: ''
                }
            } catch (e) {}
            def id = v.id ?: v.cve ?: v.name ?: 'N/A'
            def severity = ''
            def score = ''
            if (v?.ratings && v.ratings.size() > 0) {
                severity = (v.ratings[0].severity ?: '').toString().toUpperCase()
                score = v.ratings[0].score ?: ''
            } else {
                severity = (v.severity ?: '').toString().toUpperCase()
            }
            if (!severity) severity = 'UNKNOWN'
            def desc = v.description ?: v.summary ?: ''
            def link = ''
            if (v?.source?.url) {
                link = "<a href='${esc(v.source.url)}' target='_blank'>${esc(v.source.name ?: 'source')}</a>"
            } else if (v?.url) {
                link = "<a href='${esc(v.url)}' target='_blank'>advisory</a>"
            }
            def sevClass = esc(severity)
            html << """
        <tr class="${sevClass}">
          <td>${i + 1}</td>
          <td>${esc(affectedName)}</td>
          <td>${esc(affectedVersion)}</td>
          <td><pre class="small">${esc(id.toString())}</pre></td>
          <td>${esc(severity)}</td>
          <td>${esc(score.toString())}</td>
          <td><pre>${esc(desc)}</pre></td>
          <td>${link}</td>
        </tr>
"""
        }
        html << """
            </tbody>
          </table>
        </div>
        """
    }

    // Optional: All packages listing section for inventory purposes
    if (packageCount > 0) {
        html << """
        <div class="section">
          <h2>📦 All Packages (${packageCount} total)</h2>
          <table>
            <thead>
              <tr>
                <th>Package</th><th>Version</th><th>Type</th><th>purl</th>
              </tr>
            </thead>
            <tbody>
        """
        int shown = 0
        allPackages.each { c ->
            // Show up to 100 packages for easy browsing; can be adjusted or paginated
            if (shown++ < 100) {
                html << "<tr>"
                html << "<td>${esc(c.name)}</td>"
                html << "<td>${esc(c.version ?: '')}</td>"
                html << "<td>${esc(c.type ?: '')}</td>"
                html << "<td><code>${esc(c.purl ?: '')}</code></td>"
                html << "</tr>\n"
            }
        }
        if (shown == 100 && packageCount > 100) {
            html << "<tr><td colspan='4'><em>More packages not shown...</em></td></tr>"
        }
        html << """
            </tbody>
          </table>
        </div>
        """
    }

    html << "    </div>\n</body>\n</html>\n"

    writeFile file: reportFile, text: html.toString(), encoding: 'UTF-8'
    echo "Wrote ${reportFile} (size: ${new File(reportFile).length()} bytes)"

    if (publish) {
        publishHTML([reportDir: '.', reportFiles: reportFile, reportName: 'Node Vulnerability Report', keepAll: true, alwaysLinkToLastBuild: true, allowMissing: false])
    }
    archiveArtifacts artifacts: "${sbomFile}, ${vulnJsonFile}, ${reportFile}, report-style.css", allowEmptyArchive: true

    return reportFile
}
