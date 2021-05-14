
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.util.ByteArrays;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author lalex
 */
public class IpV4 {
    private byte[] macDestino;
    private byte[] macOrigen;
    private byte[] tipoLong;
    private int version;
    private int ihl;
    private IpV4Packet ipPacket;

    public IpV4(){
        macDestino = new byte[6];
        macOrigen = new byte[6];
        tipoLong = new byte[2];
        version = 0;
        ihl = 0;
        ipPacket = null;
    }

    public void analizaTrama(byte[] trama){
        this.getMacDestino(trama);
        this.getMacOrigen(trama);
        this.getTipoLong(trama);
        this.getVersion(trama);
        this.getIhl(trama);
        this.getIpPacket(trama);

    }

    public boolean esIPV4(byte b12,byte b13){
        return (b12&0xff)==8 && (b13&0xff)==0;
    }

    private void getMacDestino(byte[] trama){
        for(int i = 0;i<6;i++){
            macDestino[i] = trama[i];
        }
    }
    private void getMacOrigen(byte[] trama){
        for(int i = 6;i<12;i++){
            macOrigen[i-6] = trama[i];
        }
    }
    private void getTipoLong(byte[] trama){
        for(int i = 12;i<14;i++){
            tipoLong[i-12] = trama[i];
        }
    }
    private void getVersion(byte[] trama){
        version = (trama[14] & 0xf0)/16;
    }
    private void getIhl(byte[] trama){
        ihl = (trama[14] & 0x0f)*4;        
    }
    private void getIpPacket(byte[] trama){
        byte[] tmp_ip= Arrays.copyOfRange(trama, 14, 14 +ihl);
        try {
            ipPacket =IpV4Packet.newPacket(tmp_ip,0, tmp_ip.length);
        } catch (IllegalRawDataException ex) {
            Logger.getLogger(IpV4.class.getName()).log(Level.SEVERE, null, ex);
        }
    }


    private String tostrMacDestino(){
        String macDes = "Mac Destino: " + ByteArrays.toHexString(macDestino, "-") +"\n";
        return macDes;
    }
    private String tostrMacOrigen(){
        String macOrg = "Mac Origen: " + ByteArrays.toHexString(macOrigen, "-") +"\n";
        return macOrg;
    }
    private String tostrTipoLong(){
        String tip;
        int valor = tipoLong[1] & 255 ;
        valor += ((tipoLong[0]& 255)*256);
        tip = "Tipo/Longitud: " + ByteArrays.toHexString(tipoLong, " ")
            + " = " + valor + "\nTipo de trama: Ethernet IPv4\n";
        return tip;
    }
    private String tostrIpPacket(){
        int lt = /*(ipPacket.getHeader().getTotalLength()>0)?
                ipPacket.getHeader().getTotalLength():ipPacket.getHeader().getTotalLength()+65536;*/
            ipPacket.getHeader().getTotalLengthAsInt();

        int id= /*(ipPacket.getHeader().getIdentification()>0)?
                ipPacket.getHeader().getIdentification():ipPacket.getHeader().getIdentification()+65536;*/
            ipPacket.getHeader().getIdentificationAsInt();

        String dontFrag=(ipPacket.getHeader().getDontFragmentFlag())?"1":"0";
        String moreFrag=(ipPacket.getHeader().getMoreFragmentFlag())?"1":"0";
        String reserveFrag=(ipPacket.getHeader().getReservedFlag())?"1":"0";
        String flags = reserveFrag+dontFrag+moreFrag;
        String flagsMeaning = ("010".equals(flags))?"No fragmentar":"Fragmentar";

        int fragOffset = ipPacket.getHeader().getFragmentOffset();

        int ttl = ipPacket.getHeader().getTtlAsInt();

        String protocolo = ipPacket.getHeader().getProtocol().valueAsString();

        int checksum=ipPacket.getHeader().getHeaderChecksum();

        String ipOrigen = ipPacket.getHeader().getSrcAddr().toString();

        String ipDestino = ipPacket.getHeader().getDstAddr().toString();

        String opciones =ipPacket.getHeader().getOptions().toString();        

        String packInfo = "";
        packInfo+= "Version: "+ipPacket.getHeader().getVersion().valueAsString()+"\n"
                + "IHL: "+ipPacket.getHeader().getIhlAsInt()+"\n"
                + "Serv. Dif : "+ipPacket.getHeader().getTos().toString()+"\n"
                + "Longitud total: "+lt +"\n"
                + "Id: "+id +"\n"
                + "Flags: " +flags+" "+flagsMeaning +"\n"
                + "Fragment offset: "+ fragOffset+"\n"
                + "TTL: " + ttl+"\n"
                + "Protocolo: " + protocolo +"\n"
                + "Checksum: "+ checksum +"\n"
                + "IP Origen: "+ ipOrigen+"\n"
                + "IP Destino: "+ ipDestino+"\n"
                + "Opciones: "+opciones+"\n";

        return packInfo;
    }

    @Override
    public String toString(){
        String tramaARP;
        tramaARP = this.tostrMacDestino() +this.tostrMacOrigen() + this.tostrTipoLong()
        + this.tostrIpPacket();
        return tramaARP;
    }
}