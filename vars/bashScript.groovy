// vars/bashScript.groovy
// Usage: bashScript(scriptText, [filename])
// Runs the provided shell code using bash, using optional filename.

def call(String scriptText, String filename = 'jenkins-bash-script.sh') {
    writeFile file: filename, text: scriptText
    sh "chmod +x '${filename}'"
    // THIS IS THE FIX: must use returnStdout: true
    try {
        return sh(script: "bash '${filename}'", returnStdout: true).trim()
    } catch (Exception e) {
        return ""
    }
}
