package org.jenkins.plugins.validator

class CycloneDXGenerator implements Serializable {
    
    String generate(List plugins, List vulnerabilities) {
        def timestamp = new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'")
        def jenkins = Jenkins.instance
        
        return groovy.json.JsonOutput.toJson([
            bomFormat: "CycloneDX",
            specVersion: "1.5",
            serialNumber: "urn:uuid:${UUID.randomUUID()}",
            version: 1,
            metadata: generateMetadata(timestamp, jenkins.version),
            components: generateComponents(plugins),
            dependencies: generateDependencies(plugins),
            vulnerabilities: generateVulnerabilities(vulnerabilities)
        ])
    }
    
    private def generateMetadata(String timestamp, String jenkinsVersion) {
        return [
            timestamp: timestamp,
            tools: [
                components: [
                    [
                        type: "application",
                        name: "Jenkins Plugin Validator",
                        version: "1.0.0",
                        author: "duncanlester"
                    ]
                ]
            ],
            component: [
                type: "application",
                name: "Jenkins",
                version: jenkinsVersion,
                description: "Jenkins Automation Server"
            ]
        ]
    }
    
    private def generateComponents(List plugins) {
        return plugins.collect { plugin ->
            [
                type: "library",
                "bom-ref": "pkg:jenkins/plugin/${plugin.shortName}@${plugin.version}",
                name: plugin.shortName,
                version: plugin.version,
                description: plugin.longName,
                purl: "pkg:jenkins/plugin/${plugin.shortName}@${plugin.version}",
                properties: [
                    [name: "jenkins:enabled", value: plugin.enabled.toString()],
                    [name: "jenkins:active", value: plugin.active.toString()],
                    [name: "jenkins:hasUpdate", value: plugin.hasUpdate.toString()]
                ]
            ]
        }
    }
    
    private def generateDependencies(List plugins) {
        return plugins.collect { plugin ->
            [
                ref: "pkg:jenkins/plugin/${plugin.shortName}@${plugin.version}",
                dependsOn: plugin.dependencies.collect { dep ->
                    "pkg:jenkins/plugin/${dep.shortName}@${dep.version}"
                }
            ]
        }
    }
    
    private def generateVulnerabilities(List vulnerabilities) {
        return vulnerabilities.collect { vuln ->
            [
                id: vuln.cve,
                source: [
                    name: "Jenkins Update Center",
                    url: vuln.url ?: "https://www.jenkins.io/security/advisories/"
                ],
                ratings: [
                    [
                        severity: vuln.severity,
                        score: vuln.cvss,
                        method: "CVSSv3"
                    ]
                ],
                description: vuln.description,
                affects: [
                    [
                        ref: "pkg:jenkins/plugin/${vuln.plugin}@${vuln.version}",
                        versions: [
                            [
                                version: vuln.version,
                                status: "affected"
                            ]
                        ]
                    ]
                ]
            ]
        }
    }
}
