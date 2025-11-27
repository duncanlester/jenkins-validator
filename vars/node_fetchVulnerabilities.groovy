// Polls Dependency-Track for Node project vulnerabilities and writes them to a JSON file.
// Returns the vulnerability JSON filepath.
import groovy.json.JsonSlurper

def call(Map config = [:]) {
    String dtApiUrl = config.get('dtApiUrl') ?: env.DT_API_URL ?: 'http://dtrack-apiserver:8080'
    String dtApiKeyCredentialId = config.get('dtApiKeyCredentialId') ?: 'dependency-track-api-key'
    String projectUuid = config.get('projectUuid') ?: ''
    String vulnJsonFile = config.get('vulnJsonFile') ?: 'dt-vulnerabilities.json'
    int pollAttempts = (config.get('pollAttempts') ?: 36) as Integer
    int pollIntervalSeconds = (config.get('pollIntervalSeconds') ?: 5) as Integer

    if (!projectUuid) {
        error "node_fetchVulnerabilities: projectUuid is required"
    }
    echo "node_fetchVulnerabilities: projectUuid=${projectUuid} attempts=${pollAttempts} interval=${pollIntervalSeconds}s"

    withCredentials([string(credentialsId: dtApiKeyCredentialId, variable: 'DT_API_KEY')]) {
        int attempt = 0
        int vulnCount = 0

        while (attempt < pollAttempts) {
            attempt++
            // Get vulnerabilities JSON from Dependency-Track
            def vulnJson = sh(
                script: """
                curl -s -H "X-Api-Key: \$DT_API_KEY" "${dtApiUrl}/api/v1/vulnerability/project/${projectUuid}"
                """.stripIndent(),
                returnStdout: true
            ).trim()

            // Count vulnerabilities using JsonSlurper (no jq)
            vulnCount = 0
            if (vulnJson) {
                def parsed = null
                try {
                    parsed = new JsonSlurper().parseText(vulnJson)
                } catch (Exception e) {
                    echo "Warning: Could not parse vulnerabilities JSON: ${e.getMessage()}"
                    parsed = []
                }
                if (parsed instanceof List) {
                    vulnCount = parsed.size()
                } else if (parsed?.vulnerabilities instanceof List) {
                    vulnCount = parsed.vulnerabilities.size()
                }
            }

            echo "Attempt ${attempt}: vulnerability count = ${vulnCount}"
            if (vulnCount > 0) break
            sleep pollIntervalSeconds
        }

        // Save vulnerabilities JSON to file (last polled retrieval)
        sh """
            curl -s -H "X-Api-Key: \$DT_API_KEY" "${dtApiUrl}/api/v1/vulnerability/project/${projectUuid}" -o ${vulnJsonFile} || true
        """
        def vulnFileSize = sh(
            script: "wc -c < ${vulnJsonFile} || echo 0",
            returnStdout: true
        ).trim()
        echo "Saved vulnerabilities to ${vulnJsonFile} (size: ${vulnFileSize} bytes)"
    }
    return vulnJsonFile
}
