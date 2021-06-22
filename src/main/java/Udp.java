
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.UdpPacket;

/**
        UDP
    CLASE QUE NOS PERMITE ANALIZAR EL PROTOCOLO UDP
 */
public class Udp {
    private UdpPacket udpPacket;
    
    public Udp(byte[] trama){
        this.getUdpPacket(trama);
    }
   
    private void getUdpPacket(byte[] trama){
        //byte[] tmp_ip = Arrays.copyOfRange(trama, 34, 34 + trama[39]);
        try {
            udpPacket = UdpPacket.newPacket(trama, 0, trama.length);
        } catch (IllegalRawDataException ex) {
            Logger.getLogger(IpV4.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    public String toStrUdpPacket(){
        String udp="";
        String origen = udpPacket.getHeader().getSrcPort().toString();
        String destino = udpPacket.getHeader().getDstPort().toString();
        int lon = udpPacket.getHeader().getLengthAsInt();
        int crc = (udpPacket.getHeader().getChecksum()&65535);
        String datos = Arrays.toString(udpPacket.getHeader().getRawData());
        
        udp= "\tPueto Origen: "+ origen +"\n"
            +"\tPuerto Destino: "+ destino+"\n"
            +"\tLongitud: "+lon+"\n"
            +"\tChecksum: "+Integer.toUnsignedString(crc) +"\n"
            +"\tDatos: "+datos+"\n";
        
        return udp;
    }
}
