USER=dnovo
DATA_FOLDER=$1

for node in "${@:2}"
do
        echo Sending to $node
        scp -r $DATA_FOLDER root@$node:/root/$USER
        echo -e '\n'
done