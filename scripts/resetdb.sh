#!/bin/bash
readonly TRILLIAN_PATH=$(go list -f '{{.Dir}}' github.com/google/trillian)

echo "Completely wipe and reset database 'testTrillianDB'."
read -p "Are you sure? " -n 1 -r
if [[ $REPLY =~ ^[Yy]$ ]]
then
    # User-supplied arguments must be first. This is because some flags, such
    # as --defaults-extra-file, must be at the start.
    mysql -u root "$@" -e 'DROP DATABASE IF EXISTS testTrillianDB;'
    mysql -u root "$@" -e 'CREATE DATABASE testTrillianDB;'
    mysql -u root "$@" -e "GRANT ALL ON testTrillianDB.* TO 'testTrillianUser'@'localhost' IDENTIFIED BY 'testTrillianUserPwd';"
    mysql -u root "$@" -D testTrillianDB < ${TRILLIAN_PATH}/storage/mysql/storage.sql
fi
echo
