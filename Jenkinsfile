@Library('plugin-validator') _

pipeline {
    agent any

    options {
        buildDiscarder(logRotator(numToKeepStr: '30'))
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
    }

    stages {
        stage('Scan Plugins') {
            steps {
                script {
                    fetchInstalledPlugins()
                    fetchSecurityWarnings()
                }
            }
        }

        stage('Check for Updates') {
            steps {
                script {
                    checkForUpdates()
                }
            }
        }

        stage('Scan Vulnerabilities') {
            steps {
                script {
                    scanVulnerabilities()
                }
            }
        }

        stage('Calculate Risk Score') {
            steps {
                script {
                    calculateRiskScore()
                }
            }
        }

        stage('Generate SBOM') {
            steps {
                script {
                    generateSBOM()
                }
            }
        }

        stage('Generate Reports') {
            steps {
                script {
                    generateReports()
                }
            }
        }

        stage('Upload SBOM to Dependency-Track') {
            steps {
                script {
                    withCredentials([string(credentialsId: 'dependency-track-api-key', variable: 'DEPENDENCY_TRACK_API_KEY')]) {

                        try {
                            if (fileExists('sbom.json')) {
                                echo "📤 Uploading SBOM to Dependency-Track..."

                                // Try different URLs to find the working one
                                def urlsToTry = [
                                    'http://localhost:8081',
                                    'http://127.0.0.1:8081',
                                    'http://host.docker.internal:8081',
                                    'http://dependency-track:8080',  // Direct container access
                                    "http://\$(hostname -I | awk '{print \$1}'):8081"  // Host IP
                                ]

                                def workingUrl = null

                                echo "Testing connectivity to Dependency-Track..."
                                for (url in urlsToTry) {
                                    echo "Trying: ${url}"
                                    def result = sh(
                                        script: "curl -s -o /dev/null -w '%{http_code}' ${url}/api/version 2>&1 || echo 'FAILED'",
                                        returnStdout: true
                                    ).trim()

                                    if (result != 'FAILED' && result != '000' && result != '') {
                                        echo "✅ Success with ${url} (HTTP ${result})"
                                        workingUrl = url
                                        break
                                    } else {
                                        echo "❌ Failed: ${url}"
                                    }
                                }

                                if (workingUrl == null) {
                                    error """
                                        Cannot connect to Dependency-Track!

                                        Dependency-Track is running (confirmed), but Jenkins cannot reach it.

                                        Troubleshooting steps:
                                        1. Check if Jenkins is in Docker:
                                        docker ps | grep jenkins

                                        2. If Jenkins IS in Docker, connect the networks:
                                        docker network ls
                                        docker network connect <dependency-track-network> <jenkins-container>

                                        3. Or add to docker-compose:
                                        networks:
                                            - jenkins-network

                                        4. Verify from Jenkins server:
                                        curl http://localhost:8081/api/version
                                        """
                                }

                                echo "✅ Using URL: ${workingUrl}"

                                def sbomContent = readFile('sbom.json')
                                def sbomBase64 = sbomContent.bytes.encodeBase64().toString()

                                echo "SBOM size: ${sbomContent.length()} bytes"

                                def payload = groovy.json.JsonOutput.toJson([
                                    projectName: 'Jenkins-Plugins',
                                    projectVersion: env.BUILD_NUMBER ?: '1.0.0',
                                    autoCreate: true,
                                    bom: sbomBase64
                                ])

                                writeFile file: 'dt-payload.json', text: payload
                                writeFile file: '.dt-api-key', text: env.DEPENDENCY_TRACK_API_KEY

                                echo "Uploading SBOM to ${workingUrl}..."

                                def response = sh(
                                    script: """#!/bin/bash
                                        set +x
                                        curl -X PUT "${workingUrl}/api/v1/bom" \
                                        -H "Content-Type: application/json" \
                                        -H "X-Api-Key: \$(cat .dt-api-key)" \
                                        --data @dt-payload.json \
                                        -w "%{http_code}" \
                                        -o dt-response.json \
                                        -s
                                    """,
                                    returnStdout: true
                                ).trim()

                                echo "HTTP Status: ${response}"

                                if (response == '200' || response == '201') {
                                    echo "✅ SBOM uploaded successfully to Dependency-Track"
                                    echo "   View at: http://localhost:8081/projects"
                                } else {
                                    echo "⚠️  Upload returned status ${response}"
                                    if (fileExists('dt-response.json')) {
                                        def responseContent = readFile('dt-response.json')
                                        echo "Response: ${responseContent}"
                                    }
                                }

                            } else {
                                echo "⚠️  sbom.json not found in workspace"
                            }

                        } catch (Exception e) {
                            echo "❌ Error uploading to Dependency-Track: ${e.message}"
                            currentBuild.result = 'UNSTABLE'

                        } finally {
                            sh 'rm -f dt-payload.json dt-response.json .dt-api-key || true'
                        }
                    }
                }
            }
        }

        stage('Send Notifications') {
            steps {
                script {
                    sendSuccessNotification()
                    sendSecurityAlert()
                }
            }
        }
    }

    post {
        always {
            echo "🏁 Plugin validation complete"
            echo "📊 Build Status: ${currentBuild.result ?: 'SUCCESS'}"
        }
        unstable {
            echo "⚠️  UNSTABLE: Security vulnerabilities detected - review required"
        }
        success {
            echo "✅ SUCCESS: All plugins validated, no security issues"
        }
    }
}
