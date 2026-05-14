pipeline {
    agent {
        kubernetes {
            cloud 'kubernetes'
            inheritFrom 'platform-builder'
            yaml '''
                spec:
                  containers:
                  - name: golang
                    image: harbor.tuxgrid.com/docker.io/golang:1.24-alpine
                    command: [cat]
                    tty: true
                    resources:
                      requests:
                        cpu: 100m
                        memory: 256Mi
                      limits:
                        cpu: 1
                        memory: 512Mi
            '''
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
