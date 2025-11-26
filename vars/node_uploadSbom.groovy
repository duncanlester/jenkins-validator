import groovy.json.JsonOutput
import groovy.json.JsonSlurper
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

    def uploadToken = ''
    def projectUuid = ''
    withCredentials([string(credentialsId: dtApiKeyCredentialId, variable: 'DT_API_KEY')]) {
        try {
            // Perform SBOM upload and save response to file
            bashScript("""
                #!/usr/bin/bash
                curl -s -X PUT "${dtApiUrl}/api/v1/bom" \\
                    -H "Content-Type: application/json" -H "X-Api-Key: \$DT_API_KEY" \\
                    --data @"${payloadFile}" > dt-upload-response.json || true
                """, "upload_sbom.sh")

            // Parse upload response file to get token (indicates success)
            def responseJson = readFile('dt-upload-response.json')
            def responseObj = new JsonSlurper().parseText(responseJson)
            uploadToken = responseObj.token ?: ''

            echo "SBOM upload token: ${uploadToken}"
            if (!uploadToken) {
                error "SBOM upload failed: No upload token received"
            }
        } catch (Exception e) {
            echo "Error in SBOM upload: ${e.getMessage()}"
            error "SBOM upload step exception"
        }

        // locate project UUID (uses JsonSlurper)
        for (int i = 0; i < 10; i++) {
            try {
                bashScript("""
                    #!/usr/bin/bash
                    curl -s -H "X-Api-Key: \$DT_API_KEY" "${dtApiUrl}/api/v1/project?name=${URLEncoder.encode(projectName, 'UTF-8')}" > project-response.json
                    """, "get_project_uuid.sh")
                def projectJson = readFile('project-response.json')
                def projects = new JsonSlurper().parseText(projectJson)
                projectUuid = (projects && projects.size() > 0) ? projects[0]?.uuid : ''
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
    writeFile file: 'project-uuid.txt', text: groovy.json.JsonOutput.toJson(result)
    return [uploadToken: uploadToken, projectUuid: projectUuid]
}
