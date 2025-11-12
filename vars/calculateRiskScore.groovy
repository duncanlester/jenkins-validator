#!/usr/bin/env groovy

def call() {
    echo "📈 Calculating risk score..."
    
    def vulnCount = env.VULN_COUNT?.toInteger() ?: 0
    def outdatedCount = env.OUTDATED_COUNT?.toInteger() ?: 0
    def plugins = readJSON text: env.PLUGIN_DATA
    def totalPlugins = plugins.size()
    
    def totalScore = computeRiskScore(vulnCount, outdatedCount, totalPlugins)
    
    env.RISK_SCORE = totalScore.toString()
    
    def vulnScore = Math.min(vulnCount * 15, 60)
    def outdatedScore = ((outdatedCount / totalPlugins) * 100 * 0.3).toInteger()
    outdatedScore = Math.min(outdatedScore, 30)
    
    echo "📊 Risk Score: ${totalScore}/100"
    echo "   - Vulnerabilities: ${vulnScore} points"
    echo "   - Outdated: ${outdatedScore} points"
    echo "   - Baseline: 10 points"
    
    return totalScore
}

@NonCPS
def computeRiskScore(int vulnCount, int outdatedCount, int totalPlugins) {
    int vulnScore = Math.min(vulnCount * 15, 60)
    
    double outdatedRatio = totalPlugins > 0 ? (outdatedCount / (double)totalPlugins) : 0.0
    int outdatedScore = Math.min((int)(outdatedRatio * 100 * 0.3), 30)
    
    int baselineScore = 10
    
    int totalScore = vulnScore + outdatedScore + baselineScore
    
    return totalScore
}
