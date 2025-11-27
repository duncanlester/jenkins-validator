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

    // Install specific version of cyclonedx-npm for reproducibility
    sh """
        if ! command -v cyclonedx-npm >/dev/null 2>&1; then
          echo "Installing latest @cyclonedx/cyclonedx-npm globally..."
          npm install -g @cyclonedx/cyclonedx-npm@3 --no-progress --no-audit
        fi
        cyclonedx-npm --output-format json --output-file ${sbomFile}
        echo "SBOM generated: \$(wc -c < ${sbomFile} || echo 0) bytes"
        cat ${sbomFile} | grep purl | head -20
    """
    return sbomFile
}
