make -j 4
clear
printf "" > $1
for i in $(seq 1 $(($2 - 1)));
do
    printf "%d\n" $i >> $1
    ./ssh dhbkmanager exit 2>> $1
    sleep 1
done
printf "%d\n" $2 >> $1
./ssh dhbkmanager exit 2>> $1