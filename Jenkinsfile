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
                      ..
               '''
            }
        }
        stage('Build') {
            steps {
                echo 'Building..'
                sh '''
                   cd build
                   make -j \
                   '''

            }
        }
        stage('Test') {
            steps {
                echo 'Testing..'
                sh '''
                   echo '******************'
                   echo $PATH
                   echo '******************'
                   
                   cd build
                   sudo /usr/bin/chmod-jenkins root:root util/fusermount3
                   sudo /usr/bin/chmod-jenkins 4755 util/fusermount3
                   python3.6 -m pytest test/
                   '''
                    
            }
        }
    }
}
