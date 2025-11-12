#!/usr/bin/env groovy

def call(sbom, spdxContent, vulns) {
    echo "📊 Generating SBOM Format Comparison Report..."
    
    def cssContent = libraryResource('report-style.css')
    writeFile file: 'sbom-comparison-style.css', text: cssContent
    
    def html = buildComparisonHtml(sbom, spdxContent, vulns)
    writeFile file: 'sbom-comparison-report.html', text: html
    
    archiveArtifacts artifacts: 'sbom-comparison-report.html,sbom-comparison-style.css'
    
    echo "✅ SBOM comparison report generated"
}

@NonCPS
def buildComparisonHtml(sbom, spdxContent, vulns) {
    def html = new StringBuilder()
    def vulnCount = vulns.size()
    def componentCount = sbom.components.size()
    
    // Get sample component and vulnerability for examples
    def sampleComponent = sbom.components.size() > 0 ? sbom.components[0] : null
    def sampleVuln = sbom.vulnerabilities.size() > 0 ? sbom.vulnerabilities[0] : null
    
    html << '<!DOCTYPE html>\n'
    html << '<html lang="en">\n'
    html << '<head>\n'
    html << '    <meta charset="UTF-8">\n'
    html << '    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
    html << '    <title>SBOM Format Comparison</title>\n'
    html << '    <link rel="stylesheet" href="sbom-comparison-style.css">\n'
    html << '    <style>\n'
    html << '        .format-comparison {\n'
    html << '            display: grid;\n'
    html << '            grid-template-columns: 1fr 1fr;\n'
    html << '            gap: 24px;\n'
    html << '            margin-top: 24px;\n'
    html << '        }\n'
    html << '        .format-box {\n'
    html << '            border: 2px solid #e1e4e8;\n'
    html << '            border-radius: 8px;\n'
    html << '            padding: 20px;\n'
    html << '            background: #f6f8fa;\n'
    html << '        }\n'
    html << '        .format-box h3 {\n'
    html << '            margin-top: 0;\n'
    html << '            color: #24292e;\n'
    html << '        }\n'
    html << '        .code-example {\n'
    html << '            background: #24292e;\n'
    html << '            color: #e1e4e8;\n'
    html << '            padding: 16px;\n'
    html << '            border-radius: 6px;\n'
    html << '            overflow-x: auto;\n'
    html << '            font-family: monospace;\n'
    html << '            font-size: 12px;\n'
    html << '            line-height: 1.5;\n'
    html << '            max-height: 400px;\n'
    html << '            overflow-y: auto;\n'
    html << '        }\n'
    html << '        .feature-list {\n'
    html << '            list-style: none;\n'
    html << '            padding: 0;\n'
    html << '        }\n'
    html << '        .feature-list li {\n'
    html << '            padding: 8px 0;\n'
    html << '            border-bottom: 1px solid #e1e4e8;\n'
    html << '        }\n'
    html << '        .feature-list li:last-child {\n'
    html << '            border-bottom: none;\n'
    html << '        }\n'
    html << '        .pro { color: #28a745; font-weight: 600; }\n'
    html << '        .con { color: #dc3545; font-weight: 600; }\n'
    html << '        @media (max-width: 768px) {\n'
    html << '            .format-comparison {\n'
    html << '                grid-template-columns: 1fr;\n'
    html << '            }\n'
    html << '        }\n'
    html << '    </style>\n'
    html << '</head>\n'
    html << '<body>\n'
    html << '    <div class="container">\n'
    html << '        <div class="header">\n'
    html << '            <h1>📊 SBOM Format Comparison</h1>\n'
    html << '            <div class="header-meta">\n'
    html << "                <div><strong>Generated:</strong> ${sbom.metadata.timestamp}</div>\n"
    html << "                <div><strong>Components:</strong> ${componentCount}</div>\n"
    html << "                <div><strong>Vulnerabilities:</strong> ${vulnCount}</div>\n"
    html << '            </div>\n'
    html << '        </div>\n'
    html << '        \n'
    html << '        <div class="section">\n'
    html << '            <h2>🔍 Understanding SBOM Formats</h2>\n'
    html << '            <p class="sbom-intro">Your Jenkins plugin validator generates <strong>two different SBOM formats</strong>. Each serves a different purpose:</p>\n'
    html << '        </div>\n'
    html << '        \n'
    html << '        <div class="section">\n'
    html << '            <h2>📋 Quick Comparison</h2>\n'
    html << '            <table>\n'
    html << '                <thead>\n'
    html << '                    <tr>\n'
    html << '                        <th class="col-20">Feature</th>\n'
    html << '                        <th class="col-40">CycloneDX 1.5</th>\n'
    html << '                        <th class="col-40">SPDX 2.3</th>\n'
    html << '                    </tr>\n'
    html << '                </thead>\n'
    html << '                <tbody>\n'
    html << '                    <tr>\n'
    html << '                        <td><strong>File</strong></td>\n'
    html << '                        <td><code>sbom.json</code></td>\n'
    html << '                        <td><code>sbom.spdx</code></td>\n'
    html << '                    </tr>\n'
    html << '                    <tr>\n'
    html << '                        <td><strong>Format</strong></td>\n'
    html << '                        <td>JSON</td>\n'
    html << '                        <td>Tag-Value (text)</td>\n'
    html << '                    </tr>\n'
    html << '                    <tr>\n'
    html << '                        <td><strong>Standard Body</strong></td>\n'
    html << '                        <td>OWASP Foundation</td>\n'
    html << '                        <td>Linux Foundation (ISO Standard)</td>\n'
    html << '                    </tr>\n'
    html << '                    <tr>\n'
    html << '                        <td><strong>Vulnerabilities</strong></td>\n'
    html << '                        <td><span class="badge badge-high">✅ ${vulnCount} included</span></td>\n'
    html << '                        <td><span class="badge badge-medium">⚠️  0 (not supported in v2.3)</span></td>\n'
    html << '                    </tr>\n'
    html << '                    <tr>\n'
    html << '                        <td><strong>Primary Use</strong></td>\n'
    html << '                        <td>Security vulnerability tracking</td>\n'
    html << '                        <td>License compliance</td>\n'
    html << '                    </tr>\n'
    html << '                    <tr>\n'
    html << '                        <td><strong>Best For</strong></td>\n'
    html << '                        <td>DevSecOps, SCA tools, CVE tracking</td>\n'
    html << '                        <td>Legal teams, M&A, audits</td>\n'
    html << '                    </tr>\n'
    html << '                </tbody>\n'
    html << '            </table>\n'
    html << '        </div>\n'
    html << '        \n'
    html << '        <div class="section">\n'
    html << '            <h2>📦 Format Details</h2>\n'
    html << '            <div class="format-comparison">\n'
    html << '                <div class="format-box">\n'
    html << '                    <h3>🔷 CycloneDX 1.5</h3>\n'
    html << '                    <ul class="feature-list">\n'
    html << '                        <li><span class="pro">✅</span> Native vulnerability support with CVE mapping</li>\n'
    html << '                        <li><span class="pro">✅</span> CVSS scores and severity ratings</li>\n'
    html << '                        <li><span class="pro">✅</span> Package URLs (PURL) for component identification</li>\n'
    html << '                        <li><span class="pro">✅</span> Structured JSON format (machine-readable)</li>\n'
    html << '                        <li><span class="pro">✅</span> Direct integration with security tools</li>\n'
    html << '                        <li><span class="con">❌</span> Not an ISO standard</li>\n'
    html << '                    </ul>\n'
    html << '                    <h4 style="margin-top: 20px;">Use CycloneDX when:</h4>\n'
    html << '                    <ul class="sbom-list">\n'
    html << '                        <li>Tracking security vulnerabilities</li>\n'
    html << '                        <li>Using SCA tools (Dependency-Track, Grype)</li>\n'
    html << '                        <li>DevSecOps automation</li>\n'
    html << '                        <li>Continuous vulnerability monitoring</li>\n'
    html << '                    </ul>\n'
    html << '                </div>\n'
    html << '                \n'
    html << '                <div class="format-box">\n'
    html << '                    <h3>🔶 SPDX 2.3</h3>\n'
    html << '                    <ul class="feature-list">\n'
    html << '                        <li><span class="pro">✅</span> ISO/IEC 5962:2021 standard</li>\n'
    html << '                        <li><span class="pro">✅</span> Comprehensive license information</li>\n'
    html << '                        <li><span class="pro">✅</span> Copyright and attribution data</li>\n'
    html << '                        <li><span class="pro">✅</span> Widely recognized for compliance</li>\n'
    html << '                        <li><span class="pro">✅</span> Government/enterprise standard</li>\n'
    html << '                        <li><span class="con">❌</span> Limited vulnerability support in v2.3</li>\n'
    html << '                    </ul>\n'
    html << '                    <h4 style="margin-top: 20px;">Use SPDX when:</h4>\n'
    html << '                    <ul class="sbom-list">\n'
    html << '                        <li>License compliance audits</li>\n'
    html << '                        <li>Legal due diligence (M&A)</li>\n'
    html << '                        <li>Government contract requirements</li>\n'
    html << '                        <li>Enterprise compliance reporting</li>\n'
    html << '                    </ul>\n'
    html << '                </div>\n'
    html << '            </div>\n'
    html << '        </div>\n'
    html << '        \n'
    
    // Show actual data examples
    if (sampleComponent) {
        def cycloneSample = groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(sampleComponent))
        def spdxSample = getSPDXSample(sampleComponent)
        
        html << '        <div class="section">\n'
        html << '            <h2>💻 Real Data Example: Component</h2>\n'
        html << '            <p class="sbom-intro">Same plugin represented in both formats:</p>\n'
        html << '            <div class="format-comparison">\n'
        html << '                <div>\n'
        html << '                    <h4>CycloneDX (JSON)</h4>\n'
        html << '                    <div class="code-example">' + escapeHtml(cycloneSample) + '</div>\n'
        html << '                </div>\n'
        html << '                <div>\n'
        html << '                    <h4>SPDX (Tag-Value)</h4>\n'
        html << '                    <div class="code-example">' + escapeHtml(spdxSample) + '</div>\n'
        html << '                </div>\n'
        html << '            </div>\n'
        html << '        </div>\n'
    }
    
    if (sampleVuln) {
        def vulnSample = groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(sampleVuln))
        
        html << '        <div class="section">\n'
        html << '            <h2>🚨 Real Data Example: Vulnerability</h2>\n'
        html << '            <p class="sbom-intro">This is why CycloneDX is better for security:</p>\n'
        html << '            <div class="format-comparison">\n'
        html << '                <div>\n'
        html << '                    <h4>CycloneDX (JSON)</h4>\n'
        html << '                    <div class="code-example">' + escapeHtml(vulnSample) + '</div>\n'
        html << '                    <p style="margin-top: 12px;"><span class="badge badge-high">✅ Full vulnerability data</span></p>\n'
        html << '                </div>\n'
        html << '                <div>\n'
        html << '                    <h4>SPDX</h4>\n'
        html << '                    <div class="code-example"># SPDX 2.3 does not support\n# vulnerability data.\n#\n# Vulnerability information is\n# not included in this format.</div>\n'
        html << '                    <p style="margin-top: 12px;"><span class="badge badge-medium">⚠️  Not supported in SPDX 2.3</span></p>\n'
        html << '                </div>\n'
        html << '            </div>\n'
        html << '        </div>\n'
    }
    
    html << '        <div class="section">\n'
    html << '            <h2>🎯 Recommendation</h2>\n'
    html << '            <div class="summary-grid">\n'
    html << '                <div class="summary-item">\n'
    html << '                    <h4>For Security Teams</h4>\n'
    html << '                    <div class="summary-value color-success">Use CycloneDX</div>\n'
    html << '                    <p style="font-size: 12px; margin-top: 8px;">Import sbom.json into Dependency-Track, Grype, or other SCA tools</p>\n'
    html << '                </div>\n'
    html << '                <div class="summary-item">\n'
    html << '                    <h4>For Legal/Compliance Teams</h4>\n'
    html << '                    <div class="summary-value color-warning">Use SPDX</div>\n'
    html << '                    <p style="font-size: 12px; margin-top: 8px;">Use sbom.spdx for license audits and compliance reporting</p>\n'
    html << '                </div>\n'
    html << '            </div>\n'
    html << '            <div class="links-group" style="margin-top: 20px;">\n'
    html << '                <a href="sbom.json" class="issue-link" download>📥 Download CycloneDX (sbom.json)</a>\n'
    html << '                <a href="sbom.spdx" class="issue-link" download>📥 Download SPDX (sbom.spdx)</a>\n'
    html << '                <a href="sbom-report.html" class="issue-link">📊 View Main SBOM Report</a>\n'
    html << '            </div>\n'
    html << '        </div>\n'
    html << '        \n'
    html << '        <div class="section">\n'
    html << '            <h2>📚 Additional Resources</h2>\n'
    html << '            <ul class="sbom-list">\n'
    html << '                <li><a href="https://cyclonedx.org/">CycloneDX Official Website</a></li>\n'
    html << '                <li><a href="https://spdx.dev/">SPDX Official Website</a></li>\n'
    html << '                <li><a href="https://www.cisa.gov/sbom">CISA SBOM Resources</a></li>\n'
    html << '                <li><a href="https://www.ntia.gov/sbom">NTIA SBOM Guidelines</a></li>\n'
    html << '            </ul>\n'
    html << '        </div>\n'
    html << '    </div>\n'
    html << '</body>\n'
    html << '</html>\n'
    
    return html.toString()
}

@NonCPS
def escapeHtml(str) {
    if (!str) return ''
    return str.toString()
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
        .replace("'", '&#39;')
}

@NonCPS
def getSPDXSample(component) {
    def pkgId = "SPDPackage-${component.name.replaceAll('[^a-zA-Z0-9]', '-')}"
    return """PackageName: ${component.name}
SPDXID: ${pkgId}
PackageVersion: ${component.version}
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false

Relationship: SPDPackage-Jenkins DEPENDS_ON ${pkgId}"""
}
