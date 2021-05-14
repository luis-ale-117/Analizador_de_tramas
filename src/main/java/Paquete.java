
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

    private byte[] trama;
    private byte[] macDestino;
    private byte[] macOrigen;
    private byte[] tipoLong;
    private byte[] extra;
    private String hora;
    private int id;

    public Paquete(byte[] trama, String horaCaptura, int index) {
        this.trama = trama;
        macDestino = new byte[6];
        macOrigen = new byte[6];
        tipoLong = new byte[2];
        extra = null;
        hora = horaCaptura;
        id = index;
        this.copiaTrama(trama);
    }

    private void copiaTrama(byte[] trama) {
        this.getMacDestino(trama);
        this.getMacOrigen(trama);
        this.getTipoLong(trama);
        this.getExtra(trama);
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

    private void getExtra(byte[] trama) {
        extra = new byte[trama.length - 14];
        for (int i = 14; i < trama.length; i++) {
            extra[i - 14] = trama[i];
        }
    }

    private int valorTipo() {
        int valor = tipoLong[1] & 255;
        valor += ((tipoLong[0] & 255) * 256);
        return valor;
    }

    public String tostrMacDestino() {
        return ByteArrays.toHexString(macDestino, "-");
    }

    public String tostrMacOrigen() {
        return ByteArrays.toHexString(macOrigen, "-");
    }

    public String tostrTipoLong() {
        return ByteArrays.toHexString(tipoLong, " ");
    }

    public String tostrHora() {
        return hora;
    }

    public String tostrExtra() {
        return ByteArrays.toHexString(extra, " ");
    }

    public int tointId() {
        return id;
    }

    @Override
    public String toString() {
        String tram = "";

        /*int tipo_b1 = (trama[12]>=0)?trama[12]*256:(trama[12]+25)*256;
        int tipo_b2 = (trama[13]>=0)?trama[13]:trama[13]+256;
        int tipo = tipo_b1+tipo_b2;        
        tipo = trama[12]*255+trama[13];*/
        StringBuilder sb = new StringBuilder();
        sb.append(tram);
        sb.append("hola");
        sb.toString();
        int tipo = this.valorTipo();
        System.out.println(tipo);
        if (tipo < 1500) {//Si es IEEE 802.3 => 05 DB = 1499
            Analizador analis = new Analizador();
            analis.analizaTrama(trama);
            tram += "IEEE\n" + analis.toString();
        } else {
            switch (tipo) {
                case (int) 2048 -> {
                    //Si es IP 08 00 = 2048
                    IpV4 tramaIP = new IpV4();
                    tramaIP.analizaTrama(trama);
                    tram += "TRAMA DE PROTOCOLO IPv4\n" + tramaIP + "\n";
                }
                case (int) 2054 -> {
                    //Si es ARP 08 06 = 2054
                    Arp tramaArp = new Arp();
                    tramaArp.analizaTrama(trama);
                    tram += "TRAMA DE PROTOCOLO ARP\n" + tramaArp + "\n";
                }
                default -> // Casos no contemplados
                    tram += "TRAMA DE PROTOCOLO DESCONOCIDO ACTUALMENTE (NO ANALIZABLE) \n"
                            + "MAC destino: " + this.tostrMacDestino() + "\n"
                            + "MAC origen: " + this.tostrMacOrigen() + "\n"
                            + "Tipo: " + this.tostrTipoLong() + "\n"
                            + "El resto de la trama:\n" + ByteArrays.toHexString(extra, " ") + "\n";
            }
        }

        /*tramaARP = this.tostrMacDestino() +this.tostrMacOrigen() + this.tostrTipoLong()
                + this.tostrExtra();*/
        return tram;
    }
}
