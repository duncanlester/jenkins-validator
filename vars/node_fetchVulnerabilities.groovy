// vars/node_fetchVulnerabilities.groovy
// Polls Dependency-Track for Node project vulnerabilities and writes them to a JSON file.
// Returns the vulnerability JSON filepath.
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
            vulnCount = (sh(script: """curl -s -H "X-Api-Key: \$DT_API_KEY" "${dtApiUrl}/api/v1/vulnerability/project/${projectUuid}" | jq 'length'""", returnStdout: true).trim() ?: '0') as Integer
            echo "Attempt ${attempt}: vulnerability count = ${vulnCount}"
            if (vulnCount > 0) break
            sleep pollIntervalSeconds
        }

        sh(script: """curl -s -H "X-Api-Key: \$DT_API_KEY" "${dtApiUrl}/api/v1/vulnerability/project/${projectUuid}" -o ${vulnJsonFile} || true""")
        echo "Saved vulnerabilities to ${vulnJsonFile} (size: \$(wc -c < ${vulnJsonFile} || echo 0) bytes)"
    }
    return vulnJsonFile
}