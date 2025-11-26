// Uploads a base64-encoded SBOM for Node projects to Dependency-Track and returns the project UUID.
// Expects: dtApiUrl, dtApiKeyCredentialId, projectName, projectVersion, sbomFile.
import groovy.json.JsonOutput
import java.net.URLEncoder

def call(Map config = [:]) {
    String dtApiUrl = config.get('dtApiUrl') ?: env.DT_API_URL ?: 'http://dtrack-apiserver:8080'
    String dtApiKeyCredentialId = config.get('dtApiKeyCredentialId') ?: 'dependency-track-api-key'
    String projectName = config.get('projectName') ?: env.PROJECT_NAME ?: env.JOB_NAME ?: 'node-project'
    String projectVersion = config.get('projectVersion') ?: env.BUILD_NUMBER ?: '1.0.0'
    String sbomFile = config.get('sbomFile') ?: 'sbom.json'
    String payloadFile = config.get('payloadFile') ?: 'dt-payload.json'

    echo "node_uploadSbom: dtApiUrl=${dtApiUrl} project=${projectName}:${projectVersion} sbom=${sbomFile}"

    def sbomContent = readFile(file: sbomFile)
    def sbomBase64 = sbomContent.bytes.encodeBase64().toString()
    def payload = JsonOutput.toJson([
        projectName   : projectName,
        projectVersion: projectVersion,
        autoCreate    : true,
        bom           : sbomBase64
    ])
    writeFile file: payloadFile, text: payload

    def httpCode = '000' // Default (network/unknown error)
    def curlOutput = ''
    def projectUuid = ''
    withCredentials([string(credentialsId: dtApiKeyCredentialId, variable: 'DT_API_KEY')]) {
        try {
            curlOutput = bashScript("""
            #!/usr/bin/bash
            set -o pipefail
            echo "Uploading SBOM with:"
            ls -l "${payloadFile}"
            httpCode=\$(curl -s -o dt-upload-response.json -w "%{http_code}" -X PUT "${dtApiUrl}/api/v1/bom" \
                -H "Content-Type: application/json" -H "X-Api-Key: \\$DT_API_KEY" \
                --data @"${payloadFile}")
            echo "\${httpCode}"
            """, "upload_sbom.sh")
            curlOutput = curlOutput ? curlOutput.trim() : ''
            echo "Curl output/result: ${curlOutput}"
            sh 'cat dt-upload-response.json || true'
            httpCode = curlOutput?.trim() ?: '000'
        } catch (Exception e) {
            echo "Error in SBOM upload: ${e.getMessage()}"
            httpCode = 'exception'
        }

        echo "SBOM upload HTTP status: ${httpCode}"

        if (!(httpCode == '200' || httpCode == '201')) {
            error "SBOM upload failed (HTTP ${httpCode})"
        }

        // locate project UUID
        for (int i = 0; i < 10; i++) {
            try {
                def uuidScript = """
                #!/usr/bin/bash
                curl -s -H "X-Api-Key: \$DT_API_KEY" "${dtApiUrl}/api/v1/project?name=${URLEncoder.encode(projectName, 'UTF-8')}" | jq -r '.[0].uuid // empty'
                """
                projectUuid = bashScript(uuidScript, "get_project_uuid.sh").trim()
                if (projectUuid) break
            } catch (Exception e) {
                echo "Error during UUID lookup: ${e.getMessage()}"
            }
            sleep 2
        }
        if (!projectUuid) {
            error "Project UUID not found for project '${projectName}' after upload"
        }
        echo "Found project UUID: ${projectUuid}"
    }
    return [httpCode: httpCode, projectUuid: projectUuid]
}
