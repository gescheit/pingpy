# pingpy
versatile ping program
Main features:
- IPv6 support
- Machine-readable CLI-output

Example:
~~~
python ping.py -c 10 -i 0.1 127.0.0.1 -o json
{"count": 10, "max": 3.29, "avg": 2.17, "loss": 0, "min": 1.54}
~~~
