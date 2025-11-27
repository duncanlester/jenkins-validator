import groovy.json.JsonSlurper

@NonCPS
def extractVulnTableRows(raw) {
    def rows = []
    if (!raw?.trim()) return rows
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
        } catch (e) {
            affectedName = 'unknown'
            affectedVersion = ''
        }
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
            link = "<a href='${escapeHtml(v.source.url)}' target='_blank'>${escapeHtml(v.source.name ?: 'source')}</a>"
        } else if (v?.url) {
            link = "<a href='${escapeHtml(v.url)}' target='_blank'>advisory</a>"
        }
        def sevClass = escapeHtml(severity)
        rows << [
            index: i + 1,
            affectedName: escapeHtml(affectedName),
            affectedVersion: escapeHtml(affectedVersion),
            id: escapeHtml(id.toString()),
            severity: escapeHtml(severity),
            score: escapeHtml(score.toString()),
            desc: escapeHtml(desc),
            link: link,
            sevClass: sevClass
        ]
    }
    return rows
}

@NonCPS
def escapeHtml(s) {
    if (s == null) return ''
    s = s.toString()
    s = s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
    return s
}


def call(Map config = [:]) {
    String vulnJsonFile = config.get('vulnJsonFile') ?: 'dt-vulnerabilities.json'
    String reportFile = config.get('reportFile') ?: 'vulnerability-report.html'
    String sbomFile = config.get('sbomFile') ?: 'sbom.json'
    String projectName = config.get('projectName') ?: env.PROJECT_NAME ?: env.JOB_NAME ?: 'node-project'
    String projectVersion = config.get('projectVersion') ?: env.BUILD_NUMBER ?: '1.0.0'
    boolean publish = (config.get('publish') != null) ? config.get('publish') : true

    echo "node_renderNodeReport: input=${vulnJsonFile} output=${reportFile}"

    def vulnTableRows = []
    try {
        def raw = readFile(file: vulnJsonFile)
        vulnTableRows = extractVulnTableRows(raw)
    } catch (err) {
        echo "Warning: failed to parse ${vulnJsonFile} - ${err.message}"
        vulnTableRows = []
    }

    def html = new StringBuilder()
    html << """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Node.js Vulnerability Report - ${escapeHtml(projectName)}</title>
  <style>
    body { font-family: Arial, Helvetica, sans-serif; margin: 20px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
    th { background: #2f72b7; color: #fff; }
    .CRITICAL { background: #ff4d4f; color: #fff; }
    .HIGH { background: #ff8c00; color: #fff; }
    .MEDIUM { background: #ffd966; }
    .LOW { background: #c6efce; }
    .UNKNOWN { background: #eee; }
    .small { font-size: 0.9em; color: #333; }
    pre { white-space: pre-wrap; word-wrap: break-word; margin:0; }
  </style>
</head>
<body>
  <h1>Node.js Vulnerability Report</h1>
  <p>Project: <strong>${escapeHtml(projectName)}</strong> &nbsp; Version: <strong>${escapeHtml(projectVersion)}</strong></p>
  <p>Generated: ${new Date().toString()}</p>
  <table>
    <tr>
      <th>#</th><th>Package</th><th>Version</th><th>ID</th><th>Severity</th><th>Score</th><th>Description</th><th>Link</th>
    </tr>
"""

    vulnTableRows.each { row ->
        html << """
    <tr class="${row.sevClass}">
      <td>${row.index}</td>
      <td>${row.affectedName}</td>
      <td>${row.affectedVersion}</td>
      <td><pre class="small">${row.id}</pre></td>
      <td>${row.severity}</td>
      <td>${row.score}</td>
      <td><pre>${row.desc}</pre></td>
      <td>${row.link}</td>
    </tr>
"""
    }

    html << """
  </table>
</body>
</html>
"""
    writeFile file: reportFile, text: html.toString(), encoding: 'UTF-8'
    echo "Wrote ${reportFile} (size: ${new File(reportFile).length()} bytes)"

    if (publish) {
        publishHTML([reportDir: '.', reportFiles: reportFile, reportName: 'Node Vulnerability Report', keepAll: true, alwaysLinkToLastBuild: true, allowMissing: false])
    }
    archiveArtifacts artifacts: "${sbomFile}, ${vulnJsonFile}, ${reportFile}", allowEmptyArchive: true

    return reportFile
}
