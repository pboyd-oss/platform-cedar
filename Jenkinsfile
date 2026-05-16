pipeline {
    agent {
        kubernetes {
            cloud 'kubernetes'
            inheritFrom 'platform-golang-builder'
        }
    }

    environment {
        IMAGE = 'harbor.tuxgrid.com/platform/cedar-sidecar'
    }

    options {
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
    }

    triggers {
        pollSCM('H/5 * * * *')
    }

    stages {
        stage('Test') {
            steps {
                container('golang') {
                    sh 'cd cmd/cedar-sidecar && go test ./... -v -count=1'
                }
            }
        }
        stage('Build')      { steps { script { platformBuild() } } }
        stage('Archive')    { steps { script { platformArchive() } } }
        stage('Sign')       { steps { script { platformSign() } } }
        stage('Provenance') { steps { script { platformBuildProvenance() } } }
        stage('Deploy')     { steps { script { platformDeploy() } } }
    }
}
