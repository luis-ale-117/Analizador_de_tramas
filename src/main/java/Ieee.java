
import org.pcap4j.util.ByteArrays;

/*
    Ieee
    CLASE QUE NOS PERMITE ANALIZAR TRAMAS IEEE 802.3
 */
public class Ieee {

    private byte[] macDestino;
    private byte[] macOrigen;
    private byte[] tipoLong;
    private byte dsap;
    private byte ssap;
    private byte[] control;

    public Ieee() {
        macDestino = new byte[6];
        macOrigen = new byte[6];
        tipoLong = new byte[2];
        dsap = 0x00;
        ssap = 0x00;
        control = new byte[2];
    }

    public void analizaTrama(byte[] trama) {
        this.getMacDestino(trama);
        this.getMacOrigen(trama);
        this.getTipoLong(trama);
        this.getDsap(trama);
        this.getSsap(trama);
        this.getControl(trama);
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

    private void getDsap(byte[] trama) {
        dsap = trama[14];
    }

    private void getSsap(byte[] trama) {
        ssap = trama[15];
    }

    private void getControl(byte[] trama) {
        control[0] = trama[16];
        control[1] = trama[17];
    }

    private void printMacDestino() {
        System.out.print("Mac Destino: ");
        for (int i = 0; i < 6; i++) {
            if (i < 5) {
                System.out.printf("%02X-", macDestino[i]);
            } else {
                System.out.printf("%02X", macDestino[i]);
            }
        }
        System.out.println("");
    }

    private void printMacOrigen() {
        System.out.print("Mac Origen: ");
        for (int i = 0; i < 6; i++) {
            if (i < 5) {
                System.out.printf("%02X-", macOrigen[i]);
            } else {
                System.out.printf("%02X", macOrigen[i]);
            }
        }
        System.out.println("");
    }

    private void printTipoLong() {
        int valor = tipoLong[1] & 255;
        valor += ((tipoLong[0] & 255) * 256);
        System.out.print("Tipo/Longitud: ");
        for (int i = 0; i < 2; i++) {
            System.out.printf("%02X ", tipoLong[i]);
        }
        System.out.print("= " + valor + " en decimal");
        System.out.println("");
        if (valor < 1500) {
            System.out.println("Tipo de trama: IEEE 802.3");
            System.out.println("Longitud de trama: " + valor + " bytes");
        } else {
            System.out.println("Tipo de trama: Ethernet");
        }
    }

    private void printDsap() {
        byte aux = 1;
        aux = (byte) (aux & dsap);
        System.out.printf("DSAP: %02X ", dsap);
        if (aux == 1) {
            System.out.print("Destinatario: Grupal\n");
        } else {
            System.out.print("Destinatario: Individual\n");
        }
    }

    private void printSsap() {
        byte aux = 1;
        aux = (byte) (aux & ssap);
        System.out.printf("SSAP: %02X ", ssap);
        if (aux == 1) {
            System.out.print("C/R: Respuesta\n");
        } else {
            System.out.print("C/R: Comando\n");
        }
    }

    private void printControl() {
        int aux0 = control[0] & 255;
        aux0 = aux0 >> 1;
        int aux1 = control[1] & 255;
        aux1 = aux1 >> 1;
        int valor = tipoLong[1] & 255;
        valor += ((tipoLong[0] & 255) * 256);
        int modo = 1;//Modo normal
        String s1 = "";
        String s2 = "";

        System.out.print("Control: ");
        if (valor > 3 && (control[0] & 3) != 3) {
            modo = 2;//Modo extendido
        }
        for (int i = 0; i < modo; i++) {
            System.out.printf("%02X ", control[i]);
        }
        System.out.print(" = ");
        for (int i = 0; i < modo; i++) {
            s1 = String.format("%8s", Integer.toBinaryString(control[i] & 0xFF)).replace(' ', '0');
            System.out.printf(s1 + " ");
        }
        System.out.println("");
        /*Modo normal*/
        if (valor == 3) {
            /*Trama I*/
            if ((control[0] & 1) == 0) {
                System.out.println("Trama I (de informacion)");
                s1 = String.format("%3s", Integer.toBinaryString((aux0 >> 4) & 0xFF)).replace(' ', '0');
                System.out.println(" N(R): " + s1 + "=" + (aux0 >> 4));
                s1 = String.format("%3s", Integer.toBinaryString((aux0 & 7) & 0xFF)).replace(' ', '0');
                System.out.println(" N(S): " + s1 + "=" + (aux0 & 7));
                int pf = (aux0 & 8) >> 3;
                System.out.println(" P/F: " + pf);
            } /*Trama S*/ else if ((control[0] & 2) == 0) {
                System.out.println("Trama S (de supervision)");
                s1 = String.format("%3s", Integer.toBinaryString((aux0 >> 4) & 0xFF)).replace(' ', '0');
                System.out.println(" N(R): " + s1 + "=" + (aux0 >> 4));
                int code = aux0 >> 1;
                s1 = String.format("%2s", Integer.toBinaryString((code & 3) & 0xFF)).replace(' ', '0');
                System.out.println(" Codigo: " + s1);
                int pf = (aux0 & 8) >> 3;
                System.out.println(" P/F: " + pf);
            } /*Trama U*/ else {
                System.out.println("Trama U (sin numerar)");
                s1 = String.format("%3s", Integer.toBinaryString((aux0 >> 4) & 0xFF)).replace(' ', '0');
                System.out.print(" Codigo: " + s1 + " ");
                int code = aux0 >> 1;
                s1 = String.format("%2s", Integer.toBinaryString((code & 3) & 0xFF)).replace(' ', '0');
                System.out.println(s1);
                int pf = (aux0 & 8) >> 3;
                System.out.println(" P/F: " + pf);
            }
        } /*Modo extendido*/ else if (valor > 3) {
            /*Trama I*/
            if ((control[0] & 1) == 0) {
                System.out.println("Trama I (de informacion)");
                s1 = String.format("%7s", Integer.toBinaryString(aux0 & 0xFF)).replace(' ', '0');
                System.out.println(" N(S): " + s1 + "=" + aux0);
                s1 = String.format("%7s", Integer.toBinaryString(aux1 & 0xFF)).replace(' ', '0');
                System.out.println(" N(R): " + s1 + "=" + aux1);
                System.out.println(" P/F: " + (control[1] & 1));
            } /*Trama S*/ else if ((control[0] & 2) == 0) {
                System.out.println("Trama S (de supervision)");
                int code = aux0 >> 1;
                s1 = String.format("%2s", Integer.toBinaryString((code & 3) & 0xFF)).replace(' ', '0');
                System.out.println(" Codigo: " + s1);
                s1 = String.format("%7s", Integer.toBinaryString(aux1 & 0xFF)).replace(' ', '0');
                System.out.println(" N(R): " + s1 + "=" + aux1);
                System.out.println(" P/F: " + (control[1] & 1));
            } /*Trama U*/ else {
                System.out.println("Trama U (sin numerar)");
                s1 = String.format("%3s", Integer.toBinaryString((aux0 >> 4) & 0xFF)).replace(' ', '0');
                System.out.print(" Codigo: " + s1 + " ");
                int code = aux0 >> 1;
                s1 = String.format("%2s", Integer.toBinaryString((code & 3) & 0xFF)).replace(' ', '0');
                System.out.println(s1);
                int pf = (aux0 & 8) >> 3;
                System.out.println(" P/F: " + pf);
            }
        }

    }

    public void muestraAnalisis() {
        this.printMacDestino();
        this.printMacOrigen();
        this.printTipoLong();
        this.printDsap();
        this.printSsap();
        System.out.println("   PDU de LLC");
        this.printControl();
    }

    private String tostrMacDestino() {
        String macDes = "Mac Destino: " + ByteArrays.toHexString(macDestino, "-") + "\n";
        //System.out.print("Mac Destino: ");
        //System.out.println(ByteArrays.toHexString(macDestino, "-"));
        //System.out.println("");
        return macDes;
    }

    private String tostrMacOrigen() {
        String macOrg = "Mac Origen: " + ByteArrays.toHexString(macOrigen, "-") + "\n";
        //System.out.print("Mac Origen: ");
        //System.out.println(ByteArrays.toHexString(macOrigen, "-"));
        //System.out.println("");
        return macOrg;
    }

    private String tostrTipoLong() {
        String tip;
        int valor = tipoLong[1] & 255;
        valor += ((tipoLong[0] & 255) * 256);
        tip = "Tipo/Longitud: " + ByteArrays.toHexString(tipoLong, " ")
                + " = " + valor + " en decimal\n" + "Tipo de trama: Ethernet Arp\n";
        //System.out.print("Tipo/Longitud: ");  
        /*for(int i = 0;i<2;i++){
            System.out.printf("%02X ",tipoLong[i]);
        }*/
        //System.out.print("= " + valor +" en decimal");
        //System.out.println("");
        /*
        if(valor<1500){
            System.out.println("Tipo de trama: IEEE 802.3");
            System.out.println("Longitud de trama: " + valor+ " bytes");
        }
        else{
            System.out.println("Tipo de trama: Ethernet");
        }*/
        return tip;
    }

    private String tostrdsap() {
        //String dsap = "DSAP: " + ByteArrays.toHexString(sdap, "-") +"\n";
        byte aux = 1;
        aux = (byte) (aux & dsap);
        String dsp = "DSAP " + ByteArrays.toHexString(dsap, " ") + "\n";
        System.out.printf("DSAP: %02X ", dsap);
        if (aux == 1) {
            System.out.print("Destinatario: Grupal\n");
            dsp += "Destinatario: Grupal\n";
        } else {
            System.out.print("Destinatario: Individual\n");
            dsp += "Destinatario: Individual\n";
        }
        return dsp;
    }

    private String tostrssap() {
        //String dsap = "DSAP: " + ByteArrays.toHexString(sdap, "-") +"\n";

        byte aux = 1;
        aux = (byte) (aux & ssap);

        String ssp = "SSAP: " + ByteArrays.toHexString(dsap, " ") + "\n";
        System.out.printf("SSAP: %02X ", ssap);
        if (aux == 1) {
            System.out.print("C/R: Respuesta\n");
            ssp += "C/R: Respuesta\n";
        } else {
            System.out.print("C/R: Comando\n");
            ssp += "C/R: Comando\n";
        }
        return ssp;
    }

    private String tostrControl() {
        int aux0 = control[0] & 255;
        aux0 = aux0 >> 1;
        int aux1 = control[1] & 255;
        aux1 = aux1 >> 1;
        int valor = tipoLong[1] & 255;
        valor += ((tipoLong[0] & 255) * 256);
        int modo = 1;//Modo normal
        String s1 = "";
        String s2 = "";
        String ctrl = "Control: ";

        System.out.print("Control: ");
        if (valor > 3 && (control[0] & 3) != 3) {
            modo = 2;//Modo extendido
        }
        for (int i = 0; i < modo; i++) {
            System.out.printf("%02X ", control[i]);
            ctrl += control[i];
        }
        System.out.print(" = ");
        for (int i = 0; i < modo; i++) {
            s1 = String.format("%8s", Integer.toBinaryString(control[i] & 0xFF)).replace(' ', '0');
            System.out.printf(s1 + " ");
            ctrl += s1 + " ";
        }
        System.out.println("");
        ctrl += "\n";
        /*Modo normal*/
        if (valor == 3) {
            /*Trama I*/
            if ((control[0] & 1) == 0) {
                System.out.println("Trama I (de informacion)");
                ctrl += "Trama I (de informacion)\n";

                s1 = String.format("%3s", Integer.toBinaryString((aux0 >> 4) & 0xFF)).replace(' ', '0');
                System.out.println(" N(R): " + s1 + "=" + (aux0 >> 4));
                ctrl += " N(R): " + s1 + "=" + (aux0 >> 4) + "\n";

                s1 = String.format("%3s", Integer.toBinaryString((aux0 & 7) & 0xFF)).replace(' ', '0');
                System.out.println(" N(S): " + s1 + "=" + (aux0 & 7));
                ctrl += " N(S): " + s1 + "=" + (aux0 & 7) + "\n";
                int pf = (aux0 & 8) >> 3;
                System.out.println(" P/F: " + pf);
                ctrl += " P/F: " + pf + "\n";

            } /*Trama S*/ else if ((control[0] & 2) == 0) {
                System.out.println("Trama S (de supervision)");
                ctrl += "Trama S (de supervision)\n";
                s1 = String.format("%3s", Integer.toBinaryString((aux0 >> 4) & 0xFF)).replace(' ', '0');
                System.out.println(" N(R): " + s1 + "=" + (aux0 >> 4));
                ctrl += " N(R): " + s1 + "=" + (aux0 >> 4) + "\n";
                int code = aux0 >> 1;
                s1 = String.format("%2s", Integer.toBinaryString((code & 3) & 0xFF)).replace(' ', '0');
                System.out.println(" Codigo: " + s1);
                ctrl += " Codigo: " + s1 + "\n";
                int pf = (aux0 & 8) >> 3;
                System.out.println(" P/F: " + pf);
                ctrl += " P/F: " + pf + "\n";
            } /*Trama U*/ else {
                System.out.println("Trama U (sin numerar)");
                ctrl += "Trama U (sin numerar)";
                s1 = String.format("%3s", Integer.toBinaryString((aux0 >> 4) & 0xFF)).replace(' ', '0');
                System.out.print(" Codigo: " + s1 + " ");
                ctrl += " Codigo: " + s1 + " ";
                int code = aux0 >> 1;
                s1 = String.format("%2s", Integer.toBinaryString((code & 3) & 0xFF)).replace(' ', '0');
                System.out.println(s1);
                ctrl += s1 + "\n";
                int pf = (aux0 & 8) >> 3;
                System.out.println(" P/F: " + pf);
                ctrl += " P/F: " + pf + "\n";
            }
        } /*Modo extendido*/ else if (valor > 3) {
            /*Trama I*/
            if ((control[0] & 1) == 0) {
                //System.out.println("Trama I (de informacion)");
                ctrl += "Trama I (de informacion)\n";
                s1 = String.format("%7s", Integer.toBinaryString(aux0 & 0xFF)).replace(' ', '0');
                //System.out.println(" N(S): "+ s1+"="+aux0);
                ctrl += " N(S): " + s1 + "=" + aux0 + "\n";
                s1 = String.format("%7s", Integer.toBinaryString(aux1 & 0xFF)).replace(' ', '0');
                //System.out.println(" N(R): "+ s1+"="+aux1);
                ctrl += " N(R): " + s1 + "=" + aux1 + "\n";
                //System.out.println(" P/F: "+ (control[1] & 1));
                ctrl += " P/F: " + (control[1] & 1) + "\n";
            } /*Trama S*/ else if ((control[0] & 2) == 0) {
                System.out.println("Trama S (de supervision)");
                ctrl += "Trama S (de supervision)\n";
                int code = aux0 >> 1;
                s1 = String.format("%2s", Integer.toBinaryString((code & 3) & 0xFF)).replace(' ', '0');
                System.out.println(" Codigo: " + s1);
                ctrl += " Codigo: " + s1 + "\n";
                s1 = String.format("%7s", Integer.toBinaryString(aux1 & 0xFF)).replace(' ', '0');
                System.out.println(" N(R): " + s1 + "=" + aux1);
                ctrl += " N(R): " + s1 + "=" + aux1 + "\n";
                System.out.println(" P/F: " + (control[1] & 1));
                ctrl += " P/F: " + (control[1] & 1) + "\n";
            } /*Trama U*/ else {
                System.out.println("Trama U (sin numerar)");
                ctrl += "Trama U (sin numerar)" + "\n";
                s1 = String.format("%3s", Integer.toBinaryString((aux0 >> 4) & 0xFF)).replace(' ', '0');
                System.out.print(" Codigo: " + s1 + " ");
                ctrl += " Codigo: " + s1 + " " + "\n";
                int code = aux0 >> 1;
                s1 = String.format("%2s", Integer.toBinaryString((code & 3) & 0xFF)).replace(' ', '0');
                System.out.println(s1);
                ctrl += s1 + "\n";
                int pf = (aux0 & 8) >> 3;
                System.out.println(" P/F: " + pf);
                ctrl += " P/F: " + pf + "\n";
            }
        }
        return ctrl;
    }

    @Override
    public String toString() {
        String tramaIEEE;
        tramaIEEE = this.tostrMacDestino() + this.tostrMacOrigen() + this.tostrTipoLong()
                + this.tostrdsap() + this.tostrssap() + this.tostrControl();
        return tramaIEEE;
    }
}
