
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
    private int [] bauxiliar; // Auxiliar para banderas.
    private byte [] windowssize; // Espacio en el buffer de datos de TCP
    private byte [] checksum;
    private byte [] urgentpointer; // Nos indica donde terminan los datos urgentes
    
    public TCP()
    {
        sourceport = new byte [2];
        destinationport = new byte [2];
        sequencenumber = new byte [4];
        acknowledgmentnumber = new byte [4];
        banderas = new byte[1];
        bauxiliar = new int[8];
        windowssize = new byte [2];
        checksum = new byte[2];
        urgentpointer = new byte[2];
    }
    
    public void analisisTCP(byte[] trama)
    {
        this.getSourcePort (trama);
        this.getDestinationPort (trama);
        this.getSequenceNumber (trama);
        this.getAcknowledgmentNumber (trama);
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
    
    private void getBanderas(byte[] trama)
    {
        int convert;
        /*banderas [0] */ convert= trama [13];
        //convert = banderas [0] >> 2; 
        for(int i=0; i<8; i++)
        {
            bauxiliar[i] = convert % 2;
            convert = convert / 2;
        }
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
            urgentpointer [0] = trama[18];
            urgentpointer [1] = trama[19];
    }
    
    private String tostrSourcePort()
    {
        int ch = sourceport[1] & 255 ;
        ch += ((sourceport[0]& 255)*256);
        String sPort = "\tSource Port: " + ch/*ByteArrays.toHexString(sourceport, "-")*/ + "\n";
        return sPort;
    }
    
    private String tostrDestinationPort()
    {
        int ch = destinationport[1] & 255 ;
        ch += ((destinationport[0]& 255)*256);
        String dPort = "\tDestination Port: " + ch/*ByteArrays.toHexString(destinationport, "-") */+ "\n";
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
        String BanDer = "\t1 = Bandera activa   y   0 = Bandera inactiva. \n\tBanderas: "
                + "\n\tCWR: " + bauxiliar[7] + "\n\tECN: " + bauxiliar[6] + "\n\tUrg: " + bauxiliar[5] 
                + "\n\tACK: " + bauxiliar[4] + "\n\tPSH: " + bauxiliar[3] + "\n\tRST: " +bauxiliar[2]
                + "\n\tSYN: " + bauxiliar[1] + "\n\tFIN: " + bauxiliar[0] + "\n";
        return BanDer;
    }
    
    private String tostrWindowsSize()
    {
        int ch = windowssize[1] & 255 ;
        ch += ((windowssize[0]& 255)*256);
        String wSize = "\tWindows Size: " +ch/*ByteArrays.toHexString(windowssize, "-") */+ "\n";
        return wSize;
    }
    
    private String tostrChecksum()
    {
        int ch = checksum[1] & 255 ;
        ch += ((checksum[0]& 255)*256);
        String cSum = "\tChecksum: " + ch/*ByteArrays.toHexString(checksum, "-")*/ + "\n";
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