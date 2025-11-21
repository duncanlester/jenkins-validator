// vars/node_generateSbom.groovy
// Generates a CycloneDX SBOM for a Node.js project.
// Returns the sbom file path (string).
def call(Map config = [:]) {
    String sbomFile = config.get('sbomFile') ?: 'sbom.json'
    boolean installIfMissing = (config.get('installIfMissing') != null) ? config.get('installIfMissing') : true

    echo "node_generateSbom: sbomFile=${sbomFile} installIfMissing=${installIfMissing}"

    if (installIfMissing) {
        sh '''
            if [ -f package-lock.json ] || [ -f npm-shrinkwrap.json ]; then
              echo "Running npm ci..."
              npm ci --silent || { echo "npm ci failed"; exit 1; }
            else
              echo "No package-lock.json found, running npm install..."
              npm install --silent || { echo "npm install failed"; exit 1; }
            fi
        '''
    }

    sh """
        if ! command -v cyclonedx-npm >/dev/null 2>&1; then
          echo "Installing @cyclonedx/cyclonedx-npm globally..."
          npm install -g @cyclonedx/cyclonedx-npm --no-progress --no-audit
        fi
        cyclonedx-npm --output-file ${sbomFile}
        echo "SBOM generated: \$(wc -c < ${sbomFile} || echo 0) bytes"
    """
    return sbomFile
}