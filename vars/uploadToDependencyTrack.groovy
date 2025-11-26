#!/usr/bin/env groovy

def call(Map config = [:]) {
    def dependencyTrackUrl = config.url ?: env.DEPENDENCY_TRACK_URL
    def apiKey = config.apiKey ?: env.DEPENDENCY_TRACK_API_KEY
    def projectName = config.projectName ?: 'Jenkins-Plugins'
    def projectVersion = config.projectVersion ?: env.BUILD_NUMBER

    if (!dependencyTrackUrl) {
        echo "⚠️  Dependency-Track upload skipped: DEPENDENCY_TRACK_URL not configured"
        return
    }

    if (!apiKey) {
        echo "⚠️  Dependency-Track upload skipped: DEPENDENCY_TRACK_API_KEY not configured"
        return
    }

    echo "📤 Uploading SBOM to Dependency-Track..."
    echo "   URL: ${dependencyTrackUrl}"
    echo "   Project: ${projectName}"
    echo "   Version: ${projectVersion}"

    try {
        def sbomContent = readFile(file: 'sbom.json')
        def sbomBase64 = sbomContent.bytes.encodeBase64().toString()

        def payloadMap = [
            projectName: projectName,
            projectVersion: projectVersion,
            autoCreate: true,
            bom: sbomBase64
        ]

        def payload = groovy.json.JsonOutput.toJson(payloadMap)

        writeFile file: 'dt-payload.json', text: payload

        def curlCmd = """curl -X PUT '${dependencyTrackUrl}/api/v1/bom' \
            -H 'Content-Type: application/json' \
            -H 'X-Api-Key: ${apiKey}' \
            --data @dt-payload.json \
            -w 'HTTP_STATUS:%{http_code}' \
            -o dt-response.json \
            -s"""

        def result = sh(script: curlCmd, returnStdout: true).trim()

        echo "Response: ${result}"

        if (result.contains('HTTP_STATUS:200') || result.contains('HTTP_STATUS:201')) {
            echo "✅ SBOM uploaded successfully to Dependency-Track"
            echo "   View project at: ${dependencyTrackUrl}/projects"
        } else {
            echo "⚠️  Unexpected response from Dependency-Track"
            def responseContent = readFile(file: 'dt-response.json')
            echo "   Response: ${responseContent}"
        }

        sh 'rm -f dt-payload.json dt-response.json'

    } catch (Exception e) {
        echo "❌ Failed to upload SBOM to Dependency-Track: ${e.message}"
        echo "   This is non-blocking - continuing pipeline"
    }
}
