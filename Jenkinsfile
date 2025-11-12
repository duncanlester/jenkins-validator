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
