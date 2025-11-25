// vars/node_generateNodeReport.groovy
// Orchestrator that composes the node-specific smaller steps.
// Parameters accepted are passed through to sub-steps.
def call(Map config = [:]) {
    echo "node_generateNodeReport (orchestrator) starting..."

    def sbomFile = node_generateSbom(config)

    def projectUuid = node_uploadSbom(config + [sbomFile: sbomFile])

    def vulnJsonFile = node_fetchVulnerabilities(config + [projectUuid: projectUuid])

    def reportFile = node_renderNodeReport(config + [vulnJsonFile: vulnJsonFile, sbomFile: sbomFile])

    if (config.get('failOnHigh')) {
        def raw = readFile(vulnJsonFile)
        def vulns = []
        if (raw?.trim()) {
            vulns = new groovy.json.JsonSlurper().parseText(raw)
            if (!(vulns instanceof List)) {
                if (vulns?.vulnerabilities instanceof List) {
                    vulns = vulns.vulnerabilities
                } else {
                    if (vulns) { vulns = [vulns] }
                }
            }
        }
        int high = 0, critical = 0
        for (v in vulns) {
            def sev = (v?.severity ?: (v?.ratings && v.ratings.size() ? v.ratings[0].severity : '')).toString().toUpperCase()
            if (sev == 'HIGH') high++
            if (sev == 'CRITICAL') critical++
        }
        if (critical > 0 || high > 0) {
            error "Build failed: found ${critical} CRITICAL and ${high} HIGH vulnerabilities"
        }
    }

    echo "node_generateNodeReport completed: report=${reportFile}"
    return [sbom: sbomFile, projectUuid: projectUuid, vulnerabilities: vulnJsonFile, report: reportFile]
}