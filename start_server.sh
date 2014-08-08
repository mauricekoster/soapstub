#! /bin/bash
nohup python soap_stub.py 2>&1 >>soap_stub.log &
echo $! > soap_stub.pid
