make ssh-slh-dsa-test && clear && ./ssh-slh-dsa-test 2> error.log;
if [ $? -ne 0 ]; then
    echo "error log";
    cat error.log;
fi