pipeline {
    agent any

    stages {
        stage('Configure'){
            steps {
                sh '''
                rm -rf build;
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

                //    Actually, this is stupid - I could just as easily let jenkins
                //    run chown and chmod directly.
                //     Must be a better way.

                // For almost anything to work, fusermount3 has to be setuid root.
                // To accomplish this - in a reasonably secure manner - under
                // a Jenkins job (which normally runs as an unprivileged user)
                // we need two 'helpers' and make use of a customized suders rule file for Jenkins.
                // etc/sudoers.d/jenkins looks like this:
                //     jenkins <HOSTNAME> = (root) NOPASSWD: /usr/bin/chmod-jenkins, /usr/bin/chown-jenkins
                // The two files just call the real chown and chmod like this:
                // * Actually, they perform a basic sanity test on the parameters first
                // * for example:    dirname and basename could be checked
                // * as well as maybe even doing an 'nm' on the file to see if it
                // * contains symbols that only fusermount3 would have
                // * There are many other options to help you feel safe with this.
                //  /usr/bin/chown "$@"
                //   and
                //  /usr/bin/chmod "$@"
                // Don't forget to set executable on them !
                sh '''
                   cd build
                   sudo /usr/bin/chown-jenkins root:root util/fusermount3
                   sudo /usr/bin/chmod-jenkins 4755 util/fusermount3
                   pytest-3 test/
                   '''
            }
        }
    }
}
