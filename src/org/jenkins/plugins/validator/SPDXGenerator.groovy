package org.jenkins.plugins.validator

class SPDXGenerator implements Serializable {
    
    String generate(List plugins, List vulnerabilities) {
        def timestamp = new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'")
        def jenkins = Jenkins.instance
        
        return groovy.json.JsonOutput.toJson([
            spdxVersion: "SPDX-2.3",
            dataLicense: "CC0-1.0",
            SPDXID: "SPDXRef-DOCUMENT",
            name: "Jenkins Plugin SBOM",
            documentNamespace: "https://jenkins.io/sbom/${UUID.randomUUID()}",
            creationInfo: [
                created: timestamp,
                creators: [
                    "Tool: Jenkins Plugin Validator-1.0.0",
                    "Organization: duncanlester"
                ],
                licenseListVersion: "3.21"
            ],
            packages: generatePackages(jenkins.version, plugins),
            relationships: generateRelationships(plugins)
        ])
    }
    
    private def generatePackages(String jenkinsVersion, List plugins) {
        def packages = [
            [
                SPDXID: "SPDXRef-Jenkins",
                name: "Jenkins",
                versionInfo: jenkinsVersion,
                downloadLocation: "https://www.jenkins.io/",
                filesAnalyzed: false,
                licenseConcluded: "MIT",
                copyrightText: "NOASSERTION"
            ]
        ]
        
        packages.addAll(plugins.collect { plugin ->
            [
                SPDXID: "SPDXRef-Package-${plugin.shortName}",
                name: plugin.shortName,
                versionInfo: plugin.version,
                downloadLocation: plugin.url ?: "https://updates.jenkins.io/download/plugins/${plugin.shortName}/${plugin.version}/${plugin.shortName}.hpi",
                filesAnalyzed: false,
                licenseConcluded: "NOASSERTION",
                licenseDeclared: "NOASSERTION",
                copyrightText: "NOASSERTION",
                externalRefs: [
                    [
                        referenceCategory: "PACKAGE-MANAGER",
                        referenceType: "purl",
                        referenceLocator: "pkg:jenkins/plugin/${plugin.shortName}@${plugin.version}"
                    ]
                ]
            ]
        })
        
        return packages
    }
    
    private def generateRelationships(List plugins) {
        def relationships = [
            [
                spdxElementId: "SPDXRef-DOCUMENT",
                relationshipType: "DESCRIBES",
                relatedSpdxElement: "SPDXRef-Jenkins"
            ]
        ]
        
        relationships.addAll(plugins.collect { plugin ->
            [
                spdxElementId: "SPDXRef-Jenkins",
                relationshipType: "DEPENDS_ON",
                relatedSpdxElement: "SPDXRef-Package-${plugin.shortName}"
            ]
        })
        
        relationships.addAll(plugins.collectMany { plugin ->
            plugin.dependencies.collect { dep ->
                [
                    spdxElementId: "SPDXRef-Package-${plugin.shortName}",
                    relationshipType: "DEPENDS_ON",
                    relatedSpdxElement: "SPDXRef-Package-${dep.shortName}"
                ]
            }
        })
        
        return relationships
    }
}
