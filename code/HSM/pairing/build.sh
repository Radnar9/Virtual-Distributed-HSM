C_PROJECT=$(pwd)
RELIC=$(pwd)/relic
JAVA_PATH=/usr/lib/jvm/java-17-openjdk-amd64

mkdir -p $C_PROJECT/lib

#$C_PROJECT/src/*.c $C_PROJECT/src/pairing_imp_tate.c
gcc $C_PROJECT/src/bls_imp.c -shared -o $C_PROJECT/lib/libPairing.so -fPIC -g -L$RELIC/relic-target/lib -I$RELIC/relic-target/include -I$RELIC/include -I$JAVA_PATH/include -I$JAVA_PATH/include/linux -I$C_PROJECT/headers -lrelic