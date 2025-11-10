package org.jenkins.plugins.validator

import groovy.xml.MarkupBuilder

/**
 * PDF Generator for Jenkins Plugin Validation Reports
 * 
 * Generates PDF reports using HTML to PDF conversion via wkhtmltopdf or similar
 * For pure Groovy approach, generates HTML with print-optimized CSS
 */
class PDFGenerator implements Serializable {
    
    /**
     * Generate PDF-ready HTML report
     * This HTML is optimized for PDF conversion
     */
    String generatePDFReadyHTML(Map data) {
        def timestamp = new Date().format('yyyy-MM-dd HH:mm:ss UTC')
        
        def writer = new StringWriter()
        def html = new MarkupBuilder(writer)
        
        html.html {
            head {
                meta(charset: 'UTF-8')
                title('Jenkins Plugin Validation Report - PDF')
                style(type: 'text/css', getPDFStyles())
            }
            body {
                // Cover Page
                div(class: 'cover-page') {
                    div(class: 'cover-content') {
                        h1('🔒 Jenkins Plugin Validation Report')
                        div(class: 'cover-subtitle', 'Security Assessment & Vulnerability Analysis')
                        div(class: 'cover-meta') {
                            p("Generated: ${timestamp}")
                            p("Jenkins Version: ${data.jenkinsVersion}")
                            p("Total Plugins: ${data.totalPlugins}")
                            p("Report ID: ${UUID.randomUUID().toString().take(8)}")
                        }
                        div(class: "risk-badge risk-${data.riskRating.toLowerCase()}", data.riskRating)
                        div(class: 'cover-score', "Risk Score: ${data.riskScore}/100")
                    }
                }
                
                // Page Break
                div(class: 'page-break')
                
                // Executive Summary
                div(class: 'section') {
                    h2('Executive Summary')
                    
                    table(class: 'summary-table') {
                        tbody {
                            tr {
                                td('Total Plugins Scanned')
                                td(class: 'value', data.totalPlugins.toString())
                            }
                            tr {
                                td('Vulnerabilities Found')
                                td(class: 'value critical', data.totalVulnerabilities.toString())
                            }
                            tr(class: 'breakdown') {
                                td('  • Critical')
                                td(class: 'value', data.criticalCount.toString())
                            }
                            tr(class: 'breakdown') {
                                td('  • High')
                                td(class: 'value', data.highCount.toString())
                            }
                            tr(class: 'breakdown') {
                                td('  • Medium')
                                td(class: 'value', data.mediumCount.toString())
                            }
                            tr {
                                td('Outdated Plugins')
                                td(class: 'value', data.outdatedCount.toString())
                            }
                            tr {
                                td('Risk Rating')
                                td(class: "value risk-${data.riskRating.toLowerCase()}", data.riskRating)
                            }
                            tr {
                                td('Risk Score')
                                td(class: 'value', "${data.riskScore}/100")
                            }
                            tr {
                                td('SBOM Generated')
                                td(class: 'value', data.sbomGenerated ? '✅ Yes' : '❌ No')
                            }
                        }
                    }
                    
                    // Risk Assessment
                    h3('Risk Assessment')
                    p(getRiskAssessmentText(data.riskRating, data.riskScore))
                    
                    // Recommendations
                    h3('Immediate Actions Required')
                    ul {
                        getRecommendations(data).each { recommendation ->
                            li(recommendation)
                        }
                    }
                }
                
                // Page Break
                if (data.vulnerabilities.size() > 0) {
                    div(class: 'page-break')
                    
                    // Vulnerability Details
                    div(class: 'section') {
                        h2("🚨 Vulnerable Plugins (${data.vulnerabilities.size()})")
                        
                        data.vulnerabilities.eachWithIndex { vuln, index ->
                            div(class: 'vulnerability-card') {
                                div(class: 'vuln-header') {
                                    span(class: 'vuln-number', "#${index + 1}")
                                    span(class: 'vuln-plugin', vuln.plugin)
                                    span(class: "badge badge-${vuln.severity.toLowerCase()}", vuln.severity)
                                }
                                
                                table(class: 'vuln-details') {
                                    tbody {
                                        tr {
                                            td('CVE ID:')
                                            td(class: 'mono', vuln.cve)
                                        }
                                        tr {
                                            td('Installed Version:')
                                            td(vuln.version)
                                        }
                                        tr {
                                            td('CVSS Score:')
                                            td("${vuln.cvss}/10.0")
                                        }
                                        tr {
                                            td('Description:')
                                            td(vuln.description ?: 'N/A')
                                        }
                                        if (vuln.url) {
                                            tr {
                                                td('Reference:')
                                                td(class: 'mono small', vuln.url)
                                            }
                                        }
                                    }
                                }
                                
                                div(class: 'vuln-recommendation') {
                                    strong('Recommendation: ')
                                    span(getVulnRecommendation(vuln))
                                }
                            }
                            
                            // Page break every 3 vulnerabilities for better readability
                            if ((index + 1) % 3 == 0 && index < data.vulnerabilities.size() - 1) {
                                div(class: 'page-break')
                            }
                        }
                    }
                }
                
                // Outdated Plugins
                if (data.outdatedPlugins.size() > 0) {
                    div(class: 'page-break')
                    
                    div(class: 'section') {
                        h2("📦 Outdated Plugins (${data.outdatedPlugins.size()})")
                        p('The following plugins have updates available:')
                        
                        table(class: 'data-table') {
                            thead {
                                tr {
                                    th('#')
                                    th('Plugin Name')
                                    th('Current Version')
                                    th('Status')
                                }
                            }
                            tbody {
                                data.outdatedPlugins.eachWithIndex { plugin, index ->
                                    tr {
                                        td(class: 'center', (index + 1).toString())
                                        td(plugin.longName)
                                        td(class: 'mono', plugin.version)
                                        td(class: 'center') {
                                            span(class: 'badge badge-warning', 'UPDATE AVAILABLE')
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                // All Plugins Inventory
                div(class: 'page-break')
                
                div(class: 'section') {
                    h2("📋 Complete Plugin Inventory (${data.allPlugins.size()})")
                    
                    table(class: 'data-table small-text') {
                        thead {
                            tr {
                                th('#')
                                th('Plugin Name')
                                th('Short Name')
                                th('Version')
                                th('Status')
                            }
                        }
                        tbody {
                            data.allPlugins.eachWithIndex { plugin, index ->
                                tr {
                                    td(class: 'center', (index + 1).toString())
                                    td(plugin.longName)
                                    td(class: 'mono', plugin.shortName)
                                    td(class: 'mono', plugin.version)
                                    td(class: 'center') {
                                        span(
                                            class: "badge badge-${plugin.enabled ? 'success' : 'disabled'}", 
                                            plugin.enabled ? 'ENABLED' : 'DISABLED'
                                        )
                                    }
                                }
                                
                                // Page break for long lists
                                if ((index + 1) % 30 == 0 && index < data.allPlugins.size() - 1) {
                                    mkp.yieldUnescaped('</tbody></table>')
                                    div(class: 'page-break')
                                    h2('📋 Complete Plugin Inventory (continued)')
                                    mkp.yieldUnescaped('<table class="data-table small-text"><thead><tr><th>#</th><th>Plugin Name</th><th>Short Name</th><th>Version</th><th>Status</th></tr></thead><tbody>')
                                }
                            }
                        }
                    }
                }
                
                // SBOM Information
                if (data.sbomGenerated) {
                    div(class: 'page-break')
                    
                    div(class: 'section') {
                        h2('📦 Software Bill of Materials (SBOM)')
                        
                        p('SBOM files have been generated in the following formats:')
                        
                        ul {
                            li {
                                strong('CycloneDX 1.5: ')
                                span(class: 'mono', 'sbom-cyclonedx.json')
                            }
                            li {
                                strong('SPDX 2.3: ')
                                span(class: 'mono', 'sbom-spdx.json')
                            }
                        }
                        
                        h3('SBOM Statistics')
                        table(class: 'summary-table') {
                            tbody {
                                tr {
                                    td('Total Components')
                                    td(class: 'value', data.totalPlugins.toString())
                                }
                                tr {
                                    td('Total Dependencies')
                                    td(class: 'value', calculateDependencies(data.allPlugins).toString())
                                }
                                tr {
                                    td('Vulnerable Components')
                                    td(class: 'value', data.totalVulnerabilities.toString())
                                }
                                tr {
                                    td('Format Version')
                                    td(class: 'value', 'CycloneDX 1.5 / SPDX 2.3')
                                }
                            }
                        }
                    }
                }
                
                // Footer on last page
                div(class: 'page-break')
                div(class: 'section footer-section') {
                    h2('📞 Support & References')
                    
                    h3('Jenkins Resources')
                    ul {
                        li {
                            strong('Security Advisories: ')
                            span(class: 'mono small', 'https://www.jenkins.io/security/advisories/')
                        }
                        li {
                            strong('Plugin Manager: ')
                            span(class: 'mono small', 'https://plugins.jenkins.io/')
                        }
                        li {
                            strong('Update Center: ')
                            span(class: 'mono small', 'https://updates.jenkins.io/')
                        }
                    }
                    
                    h3('Vulnerability Databases')
                    ul {
                        li {
                            strong('NVD (National Vulnerability Database): ')
                            span(class: 'mono small', 'https://nvd.nist.gov/')
                        }
                        li {
                            strong('CVE Details: ')
                            span(class: 'mono small', 'https://www.cvedetails.com/')
                        }
                    }
                    
                    h3('SBOM Standards')
                    ul {
                        li {
                            strong('CycloneDX: ')
                            span(class: 'mono small', 'https://cyclonedx.org/')
                        }
                        li {
                            strong('SPDX: ')
                            span(class: 'mono small', 'https://spdx.dev/')
                        }
                    }
                    
                    div(class: 'report-footer') {
                        p("Generated by Jenkins Plugin Validator v1.0.0")
                        p("Report Date: ${timestamp}")
                        p("© 2025 duncanlester - MIT License")
                    }
                }
            }
        }
        
        return writer.toString()
    }
    
    private String getPDFStyles() {
        return """
            @page {
                size: A4;
                margin: 15mm;
            }
            
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                font-size: 11pt;
                line-height: 1.6;
                color: #333;
            }
            
            .cover-page {
                height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                text-align: center;
                page-break-after: always;
            }
            
            .cover-content h1 {
                font-size: 36pt;
                color: #667eea;
                margin-bottom: 20px;
            }
            
            .cover-subtitle {
                font-size: 18pt;
                color: #666;
                margin-bottom: 40px;
            }
            
            .cover-meta {
                margin: 30px 0;
                font-size: 12pt;
                color: #666;
            }
            
            .cover-meta p {
                margin: 10px 0;
            }
            
            .cover-score {
                font-size: 24pt;
                font-weight: bold;
                margin-top: 30px;
                color: #333;
            }
            
            .risk-badge {
                display: inline-block;
                padding: 15px 40px;
                border-radius: 10px;
                font-size: 20pt;
                font-weight: bold;
                margin: 20px 0;
            }
            
            .risk-badge.risk-critical {
                background: #dc3545;
                color: white;
            }
            
            .risk-badge.risk-high {
                background: #fd7e14;
                color: white;
            }
            
            .risk-badge.risk-medium {
                background: #ffc107;
                color: #333;
            }
            
            .risk-badge.risk-low {
                background: #28a745;
                color: white;
            }
            
            .page-break {
                page-break-after: always;
            }
            
            .section {
                margin-bottom: 30px;
            }
            
            h2 {
                color: #667eea;
                font-size: 20pt;
                margin: 20px 0 15px 0;
                padding-bottom: 5px;
                border-bottom: 2px solid #667eea;
            }
            
            h3 {
                color: #764ba2;
                font-size: 14pt;
                margin: 15px 0 10px 0;
            }
            
            p {
                margin: 10px 0;
                text-align: justify;
            }
            
            .summary-table {
                width: 100%;
                margin: 20px 0;
                border-collapse: collapse;
            }
            
            .summary-table td {
                padding: 12px;
                border-bottom: 1px solid #ddd;
            }
            
            .summary-table td:first-child {
                font-weight: 600;
                width: 60%;
            }
            
            .summary-table td.value {
                text-align: right;
                font-size: 14pt;
                font-weight: bold;
            }
            
            .summary-table tr.breakdown td {
                font-size: 10pt;
                padding: 8px 12px;
            }
            
            .data-table {
                width: 100%;
                border-collapse: collapse;
                margin: 15px 0;
            }
            
            .data-table th {
                background: #f8f9fa;
                padding: 10px;
                text-align: left;
                font-weight: 600;
                border-bottom: 2px solid #dee2e6;
            }
            
            .data-table td {
                padding: 8px 10px;
                border-bottom: 1px solid #dee2e6;
            }
            
            .data-table.small-text {
                font-size: 9pt;
            }
            
            .center {
                text-align: center;
            }
            
            .mono {
                font-family: 'Courier New', monospace;
                font-size: 9pt;
            }
            
            .small {
                font-size: 9pt;
            }
            
            .badge {
                display: inline-block;
                padding: 3px 10px;
                border-radius: 5px;
                font-size: 9pt;
                font-weight: bold;
            }
            
            .badge-critical {
                background: #dc3545;
                color: white;
            }
            
            .badge-high {
                background: #fd7e14;
                color: white;
            }
            
            .badge-medium {
                background: #ffc107;
                color: #333;
            }
            
            .badge-low, .badge-success {
                background: #28a745;
                color: white;
            }
            
            .badge-warning {
                background: #ffc107;
                color: #333;
            }
            
            .badge-disabled {
                background: #6c757d;
                color: white;
            }
            
            .vulnerability-card {
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 15px;
                margin: 15px 0;
                background: #f9f9f9;
            }
            
            .vuln-header {
                margin-bottom: 10px;
                padding-bottom: 10px;
                border-bottom: 1px solid #ddd;
            }
            
            .vuln-number {
                font-weight: bold;
                color: #667eea;
                margin-right: 10px;
            }
            
            .vuln-plugin {
                font-size: 12pt;
                font-weight: bold;
                margin-right: 10px;
            }
            
            .vuln-details {
                width: 100%;
                margin: 10px 0;
            }
            
            .vuln-details td {
                padding: 5px;
                vertical-align: top;
            }
            
            .vuln-details td:first-child {
                font-weight: 600;
                width: 25%;
            }
            
            .vuln-recommendation {
                margin-top: 10px;
                padding: 10px;
                background: #fff;
                border-left: 3px solid #667eea;
            }
            
            ul {
                margin: 10px 0 10px 25px;
            }
            
            li {
                margin: 5px 0;
            }
            
            .critical {
                color: #dc3545;
            }
            
            .footer-section {
                font-size: 10pt;
            }
            
            .report-footer {
                margin-top: 40px;
                padding-top: 20px;
                border-top: 1px solid #ddd;
                text-align: center;
                color: #666;
                font-size: 9pt;
            }
            
            .report-footer p {
                margin: 5px 0;
            }
        """
    }
    
    private String getRiskAssessmentText(String rating, int score) {
        switch (rating) {
            case 'CRITICAL':
                return "Your Jenkins instance has a CRITICAL risk score of ${score}/100. Immediate action is required to address the identified vulnerabilities. This level of risk indicates severe security issues that could lead to system compromise."
            case 'HIGH':
                return "Your Jenkins instance has a HIGH risk score of ${score}/100. Urgent attention is needed to address the identified vulnerabilities. These security issues should be remediated as soon as possible to prevent potential exploitation."
            case 'MEDIUM':
                return "Your Jenkins instance has a MEDIUM risk score of ${score}/100. While not immediately critical, the identified issues should be addressed in your next maintenance window. Consider planning updates for the affected plugins."
            case 'LOW':
                return "Your Jenkins instance has a LOW risk score of ${score}/100. Your security posture is good. Continue to monitor for updates and maintain regular scanning practices."
            default:
                return "Risk assessment completed."
        }
    }
    
    private List<String> getRecommendations(Map data) {
        def recommendations = []
        
        if (data.criticalCount > 0) {
            recommendations << "Update ${data.criticalCount} plugin(s) with CRITICAL vulnerabilities immediately"
        }
        
        if (data.highCount > 0) {
            recommendations << "Schedule updates for ${data.highCount} plugin(s) with HIGH severity vulnerabilities within 24-48 hours"
        }
        
        if (data.mediumCount > 0) {
            recommendations << "Plan maintenance window to address ${data.mediumCount} MEDIUM severity issues"
        }
        
        if (data.outdatedCount > 0) {
            recommendations << "Update ${data.outdatedCount} outdated plugin(s) to latest versions"
        }
        
        recommendations << "Review the SBOM files for complete dependency analysis"
        recommendations << "Schedule regular security scans (recommended: daily)"
        recommendations << "Subscribe to Jenkins Security Advisories for proactive notifications"
        
        return recommendations
    }
    
    private String getVulnRecommendation(Map vuln) {
        switch (vuln.severity) {
            case 'CRITICAL':
                return "Update immediately. Disable plugin if update is not available until patch is released."
            case 'HIGH':
                return "Update within 24-48 hours. Monitor for exploitation attempts."
            case 'MEDIUM':
                return "Update in next maintenance window. Review configuration for mitigation options."
            case 'LOW':
                return "Update when convenient. No immediate action required."
            default:
                return "Follow security best practices and update when possible."
        }
    }
    
    private int calculateDependencies(List plugins) {
        return plugins.sum { plugin -> 
            plugin.dependencies ? plugin.dependencies.size() : 0 
        } as Integer
    }
}
