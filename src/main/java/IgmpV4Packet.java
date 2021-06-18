
import java.util.Arrays;
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
public class IgmpV4Packet {
    private byte type;
    private byte reserved1;
    private byte[] checksum;    
    private byte[] reserved2;
    private byte[] numGroupRecords;
    private GroupRecord[] groupRecords;
    /*Si type es igual a 0x11*/
    private byte resvSQrv;
    private byte qqic;
    private byte[] numSources;
    private byte[][] sourceAddress;
    private byte[] groupAddress;//También para version 1 y 2
    
    public IgmpV4Packet(){
        checksum = new byte[2];
        reserved2 = new byte[2];
        numGroupRecords = new byte[2];
        groupRecords = null;
        
        numSources = new byte[2];
        sourceAddress = null;
        groupAddress = new byte[4];
    }
    public void getIgmp(byte[] igmpMessage){
        this.getType(igmpMessage);
        this.getReserved1(igmpMessage);
        this.getChecksum(igmpMessage);        
        switch (type&0xff) {
            case 0x11: {
                /*Membership Query*/
                this.getGroupAddress(igmpMessage);
                this.getResvSQrvQqic(igmpMessage);
                this.getNumSources(igmpMessage);
                this.getSourceAddress(igmpMessage);
                break;
            }
            case 0x22: {
                /*Membership Report version 3*/
                this.getReserved2(igmpMessage);
                this.getNumGroupRecords(igmpMessage);
                this.getGroupRecords(igmpMessage);
                break;
            }
            case 0x12: {
                /*Membership Report version 1*/
                this.getGroupAddress(igmpMessage);
                break;
            }
            case 0x16: {
                /*Membership Report version 2*/
                this.getGroupAddress(igmpMessage);
                break;
            }
            case 0x17: {
                /*Leave Group*/
                this.getGroupAddress(igmpMessage);
                break;
            }
            default: {
                /*Ignore */
                break;
            }
        }
    }
    private void getType(byte[] igmpMessage) {
        type = igmpMessage[0];
    }
    private void getReserved1(byte[] igmpMessage) {
        reserved1 = igmpMessage[1];
    }
    private void getChecksum(byte[] igmpMessage) {
        for(int i=2;i<4;i++){
            checksum[i-2] = igmpMessage[i];
        }
    }
    //Para las versiones 1 y 2
    private void getGroupAddress(byte[] igmpMessage) {
        for(int i=4;i<8;i++){
            groupAddress[i-4] = igmpMessage[i];
        }
    }
    private void getReserved2(byte[] igmpMessage) {
        for(int i=4;i<6;i++){
            reserved2[i-4] = igmpMessage[i];
        }
    }
    private void getNumGroupRecords(byte[] igmpMessage) {
        for(int i=6;i<8;i++){
            numGroupRecords[i-6] = igmpMessage[i];
        }
    }
    private void getGroupRecords(byte[] igmpMessage) {
        int numeroGrupos = numGroupRecords[1] & 255;
        numeroGrupos += ((numGroupRecords[0] & 255) * 256);
        
        this.groupRecords = new GroupRecord[numeroGrupos];
        
        int auxDataLen = igmpMessage[9]&255;
        int numSourcesInGroup = igmpMessage[11]&255;
        numSourcesInGroup += ((igmpMessage[10]&255)*256);
        
        int j = numSourcesInGroup*4 + auxDataLen*4;
        
        groupRecords[0] = new GroupRecord();
        groupRecords[0].getGroupRecord(Arrays.copyOfRange(igmpMessage,8,8+7+j+1));
        
        int desde;
        int hasta = 8+7+j+1;
        
        
        for(int i=1;i<numeroGrupos;i++){
            
            desde = hasta;
            
            auxDataLen = igmpMessage[desde+1]&255;
            numSourcesInGroup = igmpMessage[desde+3]&255;
            numSourcesInGroup += ((igmpMessage[desde+2]&255)*256);
            j=numSourcesInGroup*4 + auxDataLen*4;
            
            hasta = desde+ 7 +j+1;
            
            groupRecords[i] = new GroupRecord();
            groupRecords[i].getGroupRecord(Arrays.copyOfRange(igmpMessage,desde,hasta));
        }
        
        
    }
    private void getResvSQrvQqic(byte[] igmpMessage){//Get Membership query message
        resvSQrv = igmpMessage[8];
        qqic = igmpMessage[9];
    }
    private void getNumSources(byte[] igmpMessage){
        for(int i=10;i<12;i++){
            numSources[i-10] = igmpMessage[i];
        }
    }
    private void getSourceAddress(byte[] igmpMessage){
        int numeroSources = numSources[1] & 255;
        numeroSources += ((numSources[0] & 255) * 256);
        sourceAddress = new byte[numeroSources][4];
        int nextSource = 0;
        for(int i=0;i<numeroSources;i++){
            sourceAddress[i] = Arrays.copyOfRange(igmpMessage, 12+nextSource, 15+nextSource);
            nextSource += 4;
        }
    }
    
    
    private String tostrType(){
        return (type&255)+"";
    }
    private String tostrReserved1(){
        return (reserved1&255)+"";
    }
    private String tostrChecksum(){
        return ByteArrays.toHexString(checksum, " ");
    }
    private String tostrReserved2(){
        return ByteArrays.toHexString(reserved2, " ");
    }
    private String tostrNumGroupRecords(){
        int numeroGrupos = numGroupRecords[1] & 255;
        numeroGrupos += ((numGroupRecords[0] & 255) * 256);
        return numeroGrupos+"";
    }
    private String tostrGroupRecords(){
        StringBuilder grupos = new StringBuilder(80000);
        for(GroupRecord g : groupRecords){
            grupos.append(g.toString());
        }
            
        return grupos.toString();
    }
    private String tostrResvSQrv(){
        return (resvSQrv&255)+"";
    }
    private String tostrQqic(){
        return (qqic&255)+"";
    }
    private String tostrNumSources(){
        int numeroSources = numSources[1] & 255;
        numeroSources += ((numSources[0] & 255) * 256);
        return numeroSources+"";
    }
    private String tostrSourceAddress(){
        StringBuilder sources = new StringBuilder(80000);
        
        int numSour = numSources[1] & 255;
        numSour += ((numSources[0] & 255) * 256);
        
        int add1;
        int add2;
        int add3;
        int add4;
        for(int i =0 ;i<numSour;i++){
            add1 = sourceAddress[i][0]&255;
            add2 = sourceAddress[i][1]&255;
            add3 = sourceAddress[i][2]&255;
            add4 = sourceAddress[i][3]&255;
            
            sources.append(add1).append(".").append(add2).append(".").append(add3).append(".").append(add4).append("\n");
        }
            
        return sources.toString();
    }
    private String tostrGroupAddress(){
        StringBuilder sources = new StringBuilder(80000);
        
        int add1;
        int add2;
        int add3;
        int add4;
        add1 = groupAddress[0]&255;
        add2 = groupAddress[1]&255;
        add3 = groupAddress[2]&255;
        add4 = groupAddress[3]&255;
           
        sources.append(add1).append(".").append(add2).append(".").append(add3).append(".").append(add4).append("\n");

            
        return sources.toString();
    }
    
    @Override
    public String toString(){
        
        StringBuilder igmp = new StringBuilder(90000);
        igmp.append("  IGMP Message").append("\n");
        //igmp.append("\tTipo: ").append(this.tostrType()).append("\n");
       
        switch (type&0xff) {
            case 0x11: {
                /*Membership Query*/
                igmp.append("\tTipo: ").append(this.tostrType()).append(" => Membership query").append("\n");
                igmp.append("\tMax resp time: ").append(this.tostrReserved1()).append("\n");
                igmp.append("\tChecksum: ").append(this.tostrChecksum()).append("\n");
                igmp.append("\tGroup address: ").append(this.tostrGroupAddress()).append("\n");
                igmp.append("\tResv S Qrv: ").append(this.tostrResvSQrv()).append("\n");
                igmp.append("\tResv S Qrv: ").append(this.tostrQqic()).append("\n");
                igmp.append("\tNumber of sources: ").append(this.tostrNumSources()).append("\n");
                igmp.append("\tSouces:\n").append(this.tostrSourceAddress()).append("\n");
                break;
            }
            case 0x22: {
                /*Membership Report version 3*/
                igmp.append("\tTipo: ").append(this.tostrType()).append(" => Membership report version 3").append("\n");
                igmp.append("\tReserved 1: ").append(this.tostrReserved1()).append("\n");
                igmp.append("\tChecksum: ").append(this.tostrChecksum()).append("\n");
                igmp.append("\tReserved 2: ").append(this.tostrReserved2()).append("\n");
                igmp.append("\tNumber of groups: ").append(this.tostrNumGroupRecords()).append("\n");
                igmp.append("\tGroup Records:\n").append(this.tostrGroupRecords()).append("\n");
                break;
            }
            case 0x12: {
                /*Membership Report version 1*/
                igmp.append("\tTipo: ").append(this.tostrType()).append(" => Membership report version 1").append("\n");
                igmp.append("\tUnused: ").append(this.tostrReserved1()).append("\n");
                igmp.append("\tChecksum: ").append(this.tostrChecksum()).append("\n");
                igmp.append("\tGroup address: ").append(this.tostrGroupAddress()).append("\n");
                break;
            }
            case 0x16: {
                /*Membership Report version 2*/
                igmp.append("\tTipo: ").append(this.tostrType()).append(" => Membership report version 2").append("\n");
                igmp.append("\tMax resp time: ").append(this.tostrReserved1()).append("\n");
                igmp.append("\tChecksum: ").append(this.tostrChecksum()).append("\n");
                igmp.append("\tGroup address: ").append(this.tostrGroupAddress()).append("\n");
                break;
            }
            case 0x17: {
                /*Leave Group*/
                igmp.append("\tTipo: ").append(this.tostrType()).append(" => Leave Group").append("\n");
                igmp.append("\tMax resp time: ").append(this.tostrReserved1()).append("\n");
                igmp.append("\tChecksum: ").append(this.tostrChecksum()).append("\n");
                igmp.append("\tGroup address: ").append(this.tostrGroupAddress()).append("\n");
                break;
            }
            default: {
                /*Ignore */
                igmp.append("\tChecksum: ").append(this.tostrChecksum()).append("\n");
                igmp.append("\t>>UNRECOGNIZED TYPE<<\n");
                break;
            }
        }
        return igmp.toString();
    }
}
