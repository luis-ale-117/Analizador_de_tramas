
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.util.ByteArrays;

/*
    IpV4
    CLASE QUE NOS PERMITE ANALIZAR EL PROTOCOLO IPv4
 */
public class IpV4 {

    private byte[] macDestino;
    private byte[] macOrigen;
    private byte[] tipoLong;
    private int version;
    private int ihl;
    private IpV4Packet ipPacket;
    private byte[] ipData;//Datos de los demas posibles protocolos

    public IpV4() {
        macDestino = new byte[6];
        macOrigen = new byte[6];
        tipoLong = new byte[2];
        version = 0;
        ihl = 0;
        ipPacket = null;
        ipData = null;
    }

    public void analizaTrama(byte[] trama) {
        this.getMacDestino(trama);
        this.getMacOrigen(trama);
        this.getTipoLong(trama);
        this.getVersion(trama);
        this.getIhl(trama);
        this.getIpPacket(trama);
        this.getIpData(trama);
    }

    public boolean esIPV4(byte b12, byte b13) {
        return (b12 & 0xff) == 8 && (b13 & 0xff) == 0;
    }

    private void getMacDestino(byte[] trama) {
        for (int i = 0; i < 6; i++) {
            macDestino[i] = trama[i];
        }
    }

    private void getMacOrigen(byte[] trama) {
        for (int i = 6; i < 12; i++) {
            macOrigen[i - 6] = trama[i];
        }
    }

    private void getTipoLong(byte[] trama) {
        for (int i = 12; i < 14; i++) {
            tipoLong[i - 12] = trama[i];
        }
    }

    private void getVersion(byte[] trama) {
        version = (trama[14] & 0xf0) / 16;
    }

    private void getIhl(byte[] trama) {
        ihl = (trama[14] & 0x0f) * 4;
    }

    private void getIpPacket(byte[] trama) {
        byte[] tmp_ip = Arrays.copyOfRange(trama, 14, 14 + ihl);
        try {
            ipPacket = IpV4Packet.newPacket(tmp_ip, 0, tmp_ip.length);
        } catch (IllegalRawDataException ex) {
            Logger.getLogger(IpV4.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    private void getIpData(byte[] trama){
        this.ipData = Arrays.copyOfRange(trama, 14+ihl, trama.length);//Copia la trama original
    }
    
    private String tostrMacDestino() {
        String macDes = "Mac Destino: " + ByteArrays.toHexString(macDestino, "-") + "\n";
        return macDes;
    }

    private String tostrMacOrigen() {
        String macOrg = "Mac Origen: " + ByteArrays.toHexString(macOrigen, "-") + "\n";
        return macOrg;
    }

    private String tostrTipoLong() {
        String tip;
        int valor = tipoLong[1] & 255;
        valor += ((tipoLong[0] & 255) * 256);
        tip = "Tipo/Longitud: " + ByteArrays.toHexString(tipoLong, " ")
                + " = " + valor + "\nTipo de trama: Ethernet IPv4\n";
        return tip;
    }

    private String tostrIpPacket() {
        int lt
                = /*(ipPacket.getHeader().getTotalLength()>0)?
                ipPacket.getHeader().getTotalLength():ipPacket.getHeader().getTotalLength()+65536;*/ ipPacket.getHeader().getTotalLengthAsInt();

        int id
                = /*(ipPacket.getHeader().getIdentification()>0)?
                ipPacket.getHeader().getIdentification():ipPacket.getHeader().getIdentification()+65536;*/ ipPacket.getHeader().getIdentificationAsInt();

        String dontFrag = (ipPacket.getHeader().getDontFragmentFlag()) ? "1" : "0";
        String moreFrag = (ipPacket.getHeader().getMoreFragmentFlag()) ? "1" : "0";
        String reserveFrag = (ipPacket.getHeader().getReservedFlag()) ? "1" : "0";
        String flags = reserveFrag + dontFrag + moreFrag;
        String flagsMeaning = ("010".equals(flags)) ? "No fragmentar" : "Fragmentar";

        int fragOffset = ipPacket.getHeader().getFragmentOffset();

        int ttl = ipPacket.getHeader().getTtlAsInt();

        String protocolo = ipPacket.getHeader().getProtocol().valueAsString();

        int checksum = ipPacket.getHeader().getHeaderChecksum();

        String ipOrigen = ipPacket.getHeader().getSrcAddr().toString();

        String ipDestino = ipPacket.getHeader().getDstAddr().toString();

        String opciones = ipPacket.getHeader().getOptions().toString();
        /******* Info del protocolo de transporte ********/
        String packetData = "";
        switch(ipPacket.getHeader().getProtocol().value().intValue()){//switch con el protocolo
            case (int)1: {
                //ICMP
                StringBuilder icmpStr = new StringBuilder(20000);
                icmpStr.append("  ICMP Message\n");
                try {
                    IcmpV4CommonPacket icmp = IcmpV4CommonPacket.newPacket(ipData, 0, ipData.length);
                    icmpStr.append("\tType: ").append(icmp.getHeader().getType().valueAsString())
                        .append("(").append(icmp.getHeader().getType().name()).append(")\n");
                    icmpStr.append("\tCode: ").append(icmp.getHeader().getCode().valueAsString())
                            .append("(").append(icmp.getHeader().getCode().name()).append(")\n");
                    icmpStr.append("\tChecksum: ").append(icmp.getHeader().getChecksum()).append("\n");
                } catch (IllegalRawDataException ex) {
                    Logger.getLogger(IpV4.class.getName()).log(Level.SEVERE, null, ex);
                }
                packetData+=icmpStr.toString();
                break;
            }
            case (int)2: {
                // IGMP
                IgmpV4Packet igmp = new IgmpV4Packet();
                igmp.getIgmp(ipData);
                packetData += igmp.toString();
                break;
            }
            case (int)6: {
                //TCP
                packetData+="  TCP Message\n";
                TCP tcp = new TCP();
                tcp.analisisTCP(ipData);
                packetData += tcp.toString();
                break;
            }
            case (int)17: {
                // UDP
                packetData+="  UDP Message\n";
                Udp udp = new Udp(ipData);
                packetData += udp.toStrUdpPacket();
                break;
            }
            default: {
                packetData+="Protocolo de la capa de transporte desconocido\n";
                break;
            }
        }
        
        String packInfo = "";
        packInfo += "Version: " + ipPacket.getHeader().getVersion().valueAsString() + "\n"
                + "IHL: " + ipPacket.getHeader().getIhlAsInt() + "\n"
                + "Serv. Dif : " + ipPacket.getHeader().getTos().toString() + "\n"
                + "Longitud total: " + lt + "\n"
                + "Id: " + id + "\n"
                + "Flags: " + flags + " " + flagsMeaning + "\n"
                + "Fragment offset: " + fragOffset + "\n"
                + "TTL: " + ttl + "\n"
                + "Protocolo: " + protocolo + "\n"
                + "Checksum: " + checksum + "\n"
                + "IP Origen: " + ipOrigen + "\n"
                + "IP Destino: " + ipDestino + "\n"
                + "Opciones: " + opciones + "\n"
                + "Packet Data: "+packetData+"\n";
        return packInfo;
    }

    @Override
    public String toString() {
        String tramaARP;
        tramaARP = this.tostrMacDestino() + this.tostrMacOrigen() + this.tostrTipoLong()
                + this.tostrIpPacket();
        return tramaARP;
    }
}
