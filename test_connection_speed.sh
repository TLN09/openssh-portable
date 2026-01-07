make -j 4
clear
printf "" > $2
for i in $(seq 1 $(($3 - 1)));
do
    printf "%d\n" $i >> $2
    ./ssh $1 exit 2>> $2
    sleep 1
done
printf "%d\n" $3 >> $2
./ssh $1 exit 2>> $2