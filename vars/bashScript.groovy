// vars/bashScript.groovy
// Usage: bashScript(scriptText, [filename])
// Runs the provided shell code using bash, using optional filename.

def call(String scriptText, String filename = 'jenkins-bash-script.sh') {
    writeFile file: filename, text: scriptText
    sh "chmod +x '${filename}'"
    sh "bash '${filename}'"
}
