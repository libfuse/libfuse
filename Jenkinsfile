pipeline {
    agent any

    stages {
        stage('Configure'){
            steps {
                sh '''
                mkdir -p build;
                cd build;
                cmake -G "Unix Makefiles" \
                      -DOPTION_BUILD_UTILS=ON \
                      -DOPTION_BUILD_EXAMPLES=ON \
                      -DCMAKE_INSTALL_PREFIX=./install \
                      -DCMAKE_BUILD_TYPE=Debug \
                      ...
               '''
            }
        }
        stage('Build') {
            steps {
                echo 'Building..'
                sh '''
                   make -j \
                   '''

            }
        }
        stage('Test') {
            steps {
                echo 'Testing..'
                sh '''
                   sudo chown root:root util/fusermount3
                   sudo chmod 4755 util/fusermount3
                   python3.6 -m pytest test/
                   '''
                    
            }
        }
    }
}
