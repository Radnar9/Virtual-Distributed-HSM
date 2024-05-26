RELIC_DIR=$(pwd)/relic
RELIC_ZIP=relic-0.6.0.zip
#RELIC_ZIP=relic.zip
FP_PRIME=381

unzip $RELIC_DIR/zip/$RELIC_ZIP -d $RELIC_DIR/ && mkdir -p $RELIC_DIR/relic-target && cd $RELIC_DIR/relic-target && cmake -DFP_PRIME=$FP_PRIME ../ && make