# Stealthy NMAP s7-info 

Este script es una version optimizada del nse [s7-info](https://nmap.org/nsedoc/scripts/s7-info.html) preparada para generar el menor numero de paquetes posible y poder ser utilizado en entornos industriales.

Se ha reducido el numero de paquetes evitando el uso de paquetes ICMP y SNMP, y quitando una petición que se realizaba dos veces innecesariamente.

Se ha reducido la cantidad de paquetes generados de 34 a 18.

Para el desarrollo de la aplicación se ha utilizado la librería Scapy, por lo que es necesario ejecutar el comando `python3 -m pip install requirements.txt` antes de poder ejecutar la herramienta. 