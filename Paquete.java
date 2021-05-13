
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
public class Paquete {
    private byte[] macDestino;
    private byte[] macOrigen;
    private byte[] tipoLong;
    private byte[] extra;
    private String hora;
    private int id;
    
    public Paquete(byte[] trama,String horaCaptura, int index){
        macDestino = new byte[6];
        macOrigen = new byte[6];
        tipoLong = new byte[2];
        extra = null;
        hora = horaCaptura;
        id = index;
        this.copiaTrama(trama);
    }
    
    private void copiaTrama(byte[] trama){
        this.getMacDestino(trama);
        this.getMacOrigen(trama);
        this.getTipoLong(trama);
        this.getExtra(trama);
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
    private void getExtra(byte[] trama){
        extra = new byte[trama.length-14];
        for(int i = 14;i<trama.length;i++){
            extra[i-14] = trama[i];
        }
    }
    
    public String tostrMacDestino(){
        return ByteArrays.toHexString(macDestino, "-");
    }
    public String tostrMacOrigen(){
        return ByteArrays.toHexString(macOrigen, "-");
    }
    public String tostrTipoLong(){
        return ByteArrays.toHexString(tipoLong, " ");
    }
    public String tostrHora(){      
        return hora;
    }
    public String tostrExtra(){
        return ByteArrays.toHexString(extra, " ");
    }
    public int tointId(){
        return id;
    }
   
              
    @Override
    public String toString(){
        String tram;
        
        tram = "Tiempo de captura: " + hora +"\n"
                 + "Mac Destino: " + ByteArrays.toHexString(macDestino, "-") +"\n"
                 + "Mac Origen: " + ByteArrays.toHexString(macOrigen, "-") +"\n"
                 + "Tipo/Longitud: " + ByteArrays.toHexString(tipoLong, " ")+"\n"
                 + "El resto de la trama:\n" + ByteArrays.toHexString(extra, " ")+"\n";                  
        
        /*tramaARP = this.tostrMacDestino() +this.tostrMacOrigen() + this.tostrTipoLong()
                + this.tostrExtra();*/
        return tram;
    }
}
