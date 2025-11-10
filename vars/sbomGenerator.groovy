#!/usr/bin/env groovy

import org.jenkins.plugins.validator.CycloneDXGenerator
import org.jenkins.plugins.validator.SPDXGenerator

def generateSBOM() {
    echo "📋 Generating Software Bill of Materials (SBOM)..."
    
    def pluginData = readJSON text: env.PLUGIN_DATA
    def vulnData = readJSON text: env.VULNERABILITIES
    
    // Generate CycloneDX SBOM
    def cycloneDX = new CycloneDXGenerator()
    def cycloneDxSbom = cycloneDX.generate(pluginData, vulnData)
    writeFile file: 'sbom-cyclonedx.json', text: groovy.json.JsonOutput.prettyPrint(cycloneDxSbom)
    
    // Generate SPDX SBOM
    def spdx = new SPDXGenerator()
    def spdxSbom = spdx.generate(pluginData, vulnData)
    writeFile file: 'sbom-spdx.json', text: groovy.json.JsonOutput.prettyPrint(spdxSbom)
    
    archiveArtifacts artifacts: 'sbom-*.json'
    
    env.SBOM_GENERATED = 'true'
    echo "✅ SBOM generated in CycloneDX and SPDX formats"
}
