make ssh-ml-kem-auth-test && clear && ./ssh-ml-kem-auth-test 2> error.log;
if [ $? -ne 0 ]; then
    echo "error log";
    cat error.log;
fi