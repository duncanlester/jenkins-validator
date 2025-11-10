#!/usr/bin/env groovy

def calculateRisk() {
    def pluginData = readJSON text: env.PLUGIN_DATA
    def vulnData = readJSON text: env.VULNERABILITIES
    
    def criticalCount = vulnData.count { it.severity == 'CRITICAL' }
    def highCount = vulnData.count { it.severity == 'HIGH' }
    def mediumCount = vulnData.count { it.severity == 'MEDIUM' }
    def outdatedCount = Integer.parseInt(env.OUTDATED_COUNT)
    
    def riskScore = Math.min(
        (criticalCount * 40) + 
        (highCount * 20) + 
        (mediumCount * 10) +
        (outdatedCount * 2),
        100
    )
    
    def riskRating = getRiskRating(riskScore)
    
    env.RISK_SCORE = riskScore.toString()
    env.RISK_RATING = riskRating
    env.CRITICAL_COUNT = criticalCount.toString()
    env.HIGH_COUNT = highCount.toString()
    env.MEDIUM_COUNT = mediumCount.toString()
    
    echo "📊 Risk Score: ${riskScore}/100 (${riskRating})"
    echo "   - Critical: ${criticalCount}"
    echo "   - High: ${highCount}"
    echo "   - Medium: ${mediumCount}"
    echo "   - Outdated: ${outdatedCount}"
}

private def getRiskRating(int score) {
    if (score > 70) return 'CRITICAL'
    if (score > 40) return 'HIGH'
    if (score > 20) return 'MEDIUM'
    return 'LOW'
}
