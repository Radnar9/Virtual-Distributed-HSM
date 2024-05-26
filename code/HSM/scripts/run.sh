HSM_PROJECT=$(pwd)/lib
C_PROJECT=$(pwd)/pairing
RELIC=$(pwd)/pairing/relic/relic-target

export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export PATH=$PATH:$JAVA_HOME

export LD_LIBRARY_PATH=$RELIC/lib:$LD_LIBRARY_PATH

java -Djava.security.properties="./config/java.security" -Dlogback.configurationFile="./config/logback.xml" -Djava.library.path=$C_PROJECT/lib -cp "$HSM_PROJECT/*" $@