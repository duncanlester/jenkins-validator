@Library('plugin-validator') _

pipeline {
    agent any
    
    parameters {
        choice(
            name: 'REPORT_FORMAT',
            choices: ['html', 'json', 'xml', 'all'],
            description: 'Report format to generate'
        )
        booleanParam(
            name: 'GENERATE_SBOM',
            defaultValue: true,
            description: 'Generate Software Bill of Materials'
        )
    }
    
    triggers {
        cron('0 2 * * *')
    }
    
    stages {
        stage('Fetch Plugins') {
            steps {
                script {
                    pluginScanner.fetchInstalledPlugins()
                }
            }
        }
        
        stage('Fetch Security Warnings') {
            steps {
                script {
                    pluginScanner.fetchSecurityWarnings()
                }
            }
        }
        
        stage('Check for Updates') {
            steps {
                script {
                    pluginScanner.checkForUpdates()
                }
            }
        }
        
        stage('Scan for Vulnerabilities') {
            steps {
                script {
                    pluginScanner.scanVulnerabilities()
                }
            }
        }
        
        stage('Generate SBOM') {
            when {
                expression { params.GENERATE_SBOM }
            }
            steps {
                script {
                    sbomGenerator.generateSBOM()
                }
            }
        }
        
        stage('Calculate Risk Score') {
            steps {
                script {
                    riskCalculator.calculateRisk()
                }
            }
        }
        
        stage('Generate Report') {
            steps {
                script {
                    reportGenerator.generateReports()
                }
            }
        }
    }
    
    post {
        always {
            script {
                echo "🧹 Cleanup complete"
            }
        }
        
        success {
            script {
                reportGenerator.sendSuccessNotification()
            }
        }
        
        unstable {
            script {
                reportGenerator.sendSecurityAlert()
            }
        }
    }
}
