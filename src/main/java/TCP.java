
import org.pcap4j.util.ByteArrays;
/*
    TCP
    CLASE QUE PERMITE ANALIZAR EL PROTOCOLO TCP
*/
public class TCP {
    private byte [] sourceport; //Id Aplicacion de origen 
    private byte [] destinationport; //Id Aplicacion de destino
    private byte [] sequencenumber; //# De byte en el inicio
    private byte [] acknowledgmentnumber; //# De byte que se espera recibir en el siguiente segmento
    private byte [] hlen; // Logitud de la cabecera media.
    private byte [] banderas;
    private byte [] windowssize; // Espacio en el buffer de datos de TCP
    private byte [] checksum;
    private byte [] urgentpointer; // Nos indica donde terminan los datos urgentes
    
    public TCP()
    {
        sourceport = new byte [2];
        destinationport = new byte [2];
        sequencenumber = new byte [4];
        acknowledgmentnumber = new byte [4];
        hlen = new byte[1];
        banderas = new byte[1];
        windowssize = new byte [2];
        checksum = new byte[2];
        urgentpointer = new byte[1];
    }
    
    public void analisisTCP(byte[] trama)
    {
        this.getSourcePort (trama);
        this.getDestinationPort (trama);
        this.getSequenceNumber (trama);
        this.getAcknowledgmentNumber (trama);
        this.getHlen(trama);
        this.getBanderas(trama);
        this.getWindowsSize (trama);
        this.getChecksum (trama);
        this.getUrgentPointer (trama);
    }
    private void getSourcePort(byte[] trama)
    {
        for(int i=0; i<2; i++)
        {
            sourceport[i] = trama[i]; // Llenado de Datos.
        }
    }
    
    private void getDestinationPort(byte[] trama)
    {
        for(int i=0; i<2; i++)
        {
            destinationport [i] = trama[i+2]; // Llenado de Datos.
        }
    }
    
    private void getSequenceNumber(byte[] trama)
    {
        for(int i=0; i<4; i++)
        {
            sequencenumber [i] = trama[i+4]; // Llenado de Datos.
        }
    }
    
    private void getAcknowledgmentNumber(byte[] trama)
    {
        for(int i=0; i<4; i++)
        {
            acknowledgmentnumber [i] = trama[i+8]; // Llenado de Datos.
        }
    }
    
    private void getHlen(byte[] trama)
    {
            hlen [0] = trama[12];
    }
    
    private void getBanderas(byte[] trama)
    {
       //En proceso
       
    }
    
    private void getWindowsSize(byte[] trama)
    {
        for(int i=0; i<2; i++)
        {
            windowssize [i] = trama[i+14]; // Llenado de Datos.
        }
    }
    
    private void getChecksum(byte[] trama)
    {
        for(int i=0; i<2; i++)
        {
            checksum [i] = trama[i+16];
        }
    }
    
    private void getUrgentPointer(byte[] trama)
    {
            urgentpointer [0] = trama[19];
    }
    
    private String tostrSourcePort()
    {
        String sPort = "\tSource Port: " + ByteArrays.toHexString(sourceport, "-") + "\n";
        return sPort;
    }
    
    private String tostrDestinationPort()
    {
        String dPort = "\tDestination Port: " + ByteArrays.toHexString(destinationport, "-") + "\n";
        return dPort;
    }
    
    private String tostrSequenceNumber()
    {
        String sNumber = "\tSequence Number; " + ByteArrays.toHexString(sequencenumber, "-") + "\n";
        return sNumber;
    }
    
    private String tostrAcknowledgmentNumber()
    {
        String ackNumber = "\tAcknowledgment Number: " + ByteArrays.toHexString(acknowledgmentnumber, "-") + "\n";
        return ackNumber;
    }
    
    private String tostrBanderas()
    {
        String BanDer = "\tBanderas: \n" ;
        return BanDer;
    }
    
    private String tostrWindowsSize()
    {
        String wSize = "\tWindows Size: " + ByteArrays.toHexString(windowssize, "-") + "\n";
        return wSize;
    }
    
    private String tostrChecksum()
    {
        String cSum = "\tChecksum: " + ByteArrays.toHexString(checksum, "-") + "\n";
        return cSum;
    }
    
    private String tostrUrgentPointer()
    {
        String uPointer = "\tUrgent Pointer: " + ByteArrays.toHexString(urgentpointer, "-") + "\n";
        return uPointer;
    }

    @Override
    public String toString()
    {
        String tramaTCP;
        tramaTCP = this.tostrSourcePort() + this.tostrDestinationPort() 
                + this.tostrSequenceNumber() + this.tostrAcknowledgmentNumber() + this.tostrBanderas()
                + this.tostrWindowsSize() + this.tostrChecksum() + this.tostrUrgentPointer();
        return tramaTCP;
    }

                }