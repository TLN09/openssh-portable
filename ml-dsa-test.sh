make ssh-ml-dsa-test && clear && ./ssh-ml-dsa-test 2> error.log;
if [ $? -ne 0 ]; then
    echo "error log";
    cat error.log;
fi