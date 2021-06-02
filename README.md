# Proyecto_Redes
Respositorio del proyecto de redes, el cual es un sniffer que
intente asemejar algunas funcionalidades de WireShark. Actualmente:
- Captura n tramas o por un tiempo t asignables en la GUI
- La captura de tramas se puede filtrar paquetes de acuerdo a TCPDump
- Los paquetes analizables pueden ser tipo IEEE 802.3 o Ethernet con protocolos ARP, IPv4
- Se puede seleccionar la Interfaz de Red desde la GUI

Falta:
- Analizar las tramas desde un archivo .pcap
- Guardar las tramas en un archivo .pcap
- Generar estadísticas de los paquetes capturados
- Analizar protocolos de IP que sean ICMP, IGMP, TCP, UDP
