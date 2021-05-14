
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
public class Arp {
    private byte[] macDestino;
    private byte[] macOrigen;
    private byte[] tipoLong;
    private byte[] hardType;//Tipo de hardware
    private byte[] protType;//Tipo de protocolo
    private byte hardLength;//Longitud MAC
    private byte protLength;//Longitud IP
    private byte[] opCode;
    private byte[] senderHardAdd;//Mac Origen 
    private byte[] senderProtAdd;//Ip Origen
    private byte[] targetHardAdd;//Mac Destino
    private byte[] targetProtAdd;//Mac Origen
    
    public Arp(){
        macDestino = new byte[6];
        macOrigen = new byte[6];
        tipoLong = new byte[2];
        hardType = new byte[2];
        protType = new byte[2];
        hardLength = 6;
        protLength = 4;
        opCode = new byte[2];
        senderHardAdd = new byte[hardLength];
        senderProtAdd = new byte[protLength];
        targetHardAdd = new byte[hardLength];
        targetProtAdd = new byte[protLength];
    }
    
    public void analizaTrama(byte[] trama){
        this.getMacDestino(trama);
        this.getMacOrigen(trama);
        this.getTipoLong(trama);
        this.getHardType(trama);
        this.getProtType(trama);
        this.getHardLength(trama);
        this.getProtLength(trama);
        this.getOpCode(trama);
        this.getSenderHardAdd(trama);
        this.getSenderProtAdd(trama);
        this.getTargetHardAdd(trama);
        this.getTargetProtAdd(trama);
    }
    
    public boolean esArp(byte[] trama){
        int valor = tipoLong[1] & 255 ;
        valor += ((tipoLong[0]& 255)*256);
        return valor == 2056;
        //return (trama[12]&255)==8 && (trama[13]&255)==6;
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
    private void getHardType(byte[] trama){//2 bytes
        for(int i = 14;i<16;i++){
            hardType[i-14] = trama[i];
        }
    }
    private void getProtType(byte[] trama){
        for(int i = 16;i<18;i++){
            protType[i-16] = trama[i];
        }
    }
    private void getHardLength(byte[] trama){
            hardLength = trama[18];
    }
    private void getProtLength(byte[] trama){
            protLength = trama[19];
    }
    private void getOpCode(byte[] trama){
        for(int i = 20;i<22;i++){
            opCode[i-20] = trama[i];
        }
    }
    private void getSenderHardAdd(byte[] trama){
        int hl = hardLength & 255 ;
        senderHardAdd = new byte[hl];
        for(int i = 22;i<(hl+22);i++){
            senderHardAdd[i-22] = trama[i];
        }   
    }
    private void getSenderProtAdd(byte[] trama){
        senderProtAdd = new byte[protLength];
        int aux_pos = 22 + hardLength;//22+6
        for(int i = aux_pos;i<(protLength+aux_pos);i++){
            senderProtAdd[i-aux_pos] = trama[i];
        }
    }
    private void getTargetHardAdd(byte[] trama){
        targetHardAdd = new byte[hardLength];
        int aux_pos = 22 + hardLength + protLength;
        for(int i = aux_pos;i<(hardLength+aux_pos);i++){
            targetHardAdd[i-aux_pos] = trama[i];
        }
    }
    private void getTargetProtAdd(byte[] trama){
        targetProtAdd = new byte[protLength];
        int aux_pos = 22 + 2*hardLength + protLength;
        for(int i = aux_pos;i<(protLength+aux_pos);i++){
            targetProtAdd[i-aux_pos] = trama[i];
        }
    }
    
    private String tostrMacDestino(){
        String macDes = "Mac Destino: " + ByteArrays.toHexString(macDestino, "-") +"\n";
        //System.out.print("Mac Destino: ");
        //System.out.println(ByteArrays.toHexString(macDestino, "-"));
        //System.out.println("");
        return macDes;
    }
    private String tostrMacOrigen(){
        String macOrg = "Mac Origen: " + ByteArrays.toHexString(macOrigen, "-") +"\n";
        //System.out.print("Mac Origen: ");
        //System.out.println(ByteArrays.toHexString(macOrigen, "-"));
        //System.out.println("");
        return macOrg;
    }
    private String tostrTipoLong(){
        String tip;
        int valor = tipoLong[1] & 255 ;
        valor += ((tipoLong[0]& 255)*256);
        tip = "Tipo/Longitud: " + ByteArrays.toHexString(tipoLong, " ")
            + " = " + valor +" en decimal\n" + "Tipo de trama: Ethernet Arp\n";
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
    private String tostrHardType(){
        String hardtip;
        int valor = hardType[1] & 255 ;
        valor += ((hardType[0]& 255)*256);
        hardtip = "Tipo de Hardware: "+ByteArrays.toHexString(hardType, " ")+" = "+ valor +"\n";
        //System.out.print("Mac Origen: ");
        //System.out.println(ByteArrays.toHexString(macOrigen, "-"));
        //System.out.println("");
        return hardtip;
    }
    private String tostrProtType(){
        String prottip;
        int valor = protType[1] & 255 ;
        valor += ((protType[0]& 255)*256);
        prottip = "Tipo de Protocolo: "+ByteArrays.toHexString(protType, " ")+" = "+ valor +"\n";
        //System.out.print("Mac Origen: ");
        //System.out.println(ByteArrays.toHexString(macOrigen, "-"));
        //System.out.println("");
        return prottip;
    }
    private String tostrHardLenght(){
        String hardlen;
        int valor = hardLength & 255 ;
        hardlen = "Longitud de direccion MAC: "+ valor +" en decimal\n";
        //System.out.print("Mac Origen: ");
        //System.out.println(ByteArrays.toHexString(macOrigen, "-"));
        //System.out.println("");
        return hardlen;
    }
    private String tostrProtLenght(){
        String protlen;
        int valor = protLength & 255 ;
        protlen = "Longitud de direccion IP: "+ valor +" en decimal\n";
        //System.out.print("Mac Origen: ");
        //System.out.println(ByteArrays.toHexString(macOrigen, "-"));
        //System.out.println("");
        return protlen;
    }
    private String tostrOpCode(){
        String opc;
        int valor = opCode[1] & 255 ;
        valor += ((opCode[0]& 255)*256);
        String codSignifica = "";
        
        if(valor == 1){
            codSignifica= "ARP Request";
        }else if(valor ==2){
            codSignifica= "ARP Reply";
        }else if(valor ==3){
            codSignifica= "RARP Request";
        }else if(valor ==4){
            codSignifica= "RARP Reply";
        }else if(valor ==5){
            codSignifica= "DRARP Request";
        }else if(valor ==6){
            codSignifica= "DRARP Reply";
        }else if(valor ==7){
            codSignifica= "DRARP Error";
        }else if(valor ==8){
            codSignifica= "InARP Request";
        }else if(valor ==9){
            codSignifica= "InARP Reply";
        }else{
            codSignifica= "Unknown";
        }
                
        opc = "Opcode: "+ByteArrays.toHexString(opCode, " ")+" = "+ valor +" / "+ codSignifica+"\n";
        //System.out.print("Mac Origen: ");
        //System.out.println(ByteArrays.toHexString(macOrigen, "-"));
        //System.out.println("");
        return opc;
    }
    private String tostrSenderHardAdd(){        
        String sendHardAdd = "Direccion MAC origen: " + ByteArrays.toHexString(senderHardAdd, "-") +"\n";        
        //System.out.print("Mac Destino: ");
        //System.out.println(ByteArrays.toHexString(macDestino, "-"));
        //System.out.println("");
        return sendHardAdd;
    }
    private String tostrSenderProtAdd(){
        String ip="";
        for(int i=0;i<protLength;i++){
            ip += ""+(senderProtAdd[i]&255);
            if(i<(protLength-1))
                ip+= ".";
        }
        String sendProtAdd = "Direccion IP origen: " + ip +"\n";
        //System.out.print("Mac Destino: ");
        //System.out.println(ByteArrays.toHexString(macDestino, "-"));
        //System.out.println("");
        return sendProtAdd;
    }
    private String tostrTargetHardAdd(){
        String targHardAdd = "Direccion MAC destino: " + ByteArrays.toHexString(targetHardAdd, "-") +"\n";
        //System.out.print("Mac Destino: ");
        //System.out.println(ByteArrays.toHexString(macDestino, "-"));
        //System.out.println("");
        return targHardAdd;
    }
    private String tostrTargetProtAdd(){
        String ip="";
        for(int i=0;i<protLength;i++){
            ip += ""+(targetProtAdd[i]&255);
            if(i<(protLength-1))
                ip+= ".";
        }
        String targProtAdd = "Direccion IP destino: " + ip +"\n";
        //System.out.print("Mac Destino: ");
        //System.out.println(ByteArrays.toHexString(macDestino, "-"));
        //System.out.println("");
        return targProtAdd;
    }        
    @Override
    public String toString(){
        String tramaARP;
        tramaARP = this.tostrMacDestino() +this.tostrMacOrigen() +this.tostrTipoLong()
            + this.tostrHardType() + this.tostrProtType() + this.tostrHardLenght()
            + this.tostrProtLenght() + this.tostrOpCode() + this.tostrSenderHardAdd()
            + this.tostrSenderProtAdd() + this.tostrTargetHardAdd() 
            + tostrTargetProtAdd();
        return tramaARP;
    }
}
