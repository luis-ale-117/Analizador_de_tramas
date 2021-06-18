
import java.util.Arrays;
import org.pcap4j.util.ByteArrays;

public class GroupRecord {
    private byte recordType;
    private byte auxDataLen;
    private byte[] numberOfSources;
    private byte[] multicastAddress;
    private byte[][] sourceAddress;
    private byte[] auxiliaryData;

    public GroupRecord() {
        numberOfSources = new byte[2];
        multicastAddress = new byte[4];
        sourceAddress = null;
        auxiliaryData = null;
    }
    public void getGroupRecord(byte[] grupo){
        recordType = grupo[0];
        auxDataLen = grupo[1];
        numberOfSources[0] = grupo[2];
        numberOfSources[1] = grupo[3];
        multicastAddress[0] = grupo[4];
        multicastAddress[1] = grupo[5];
        multicastAddress[2] = grupo[6];
        multicastAddress[3] = grupo[7];
        
        int numSour = numberOfSources[1] & 255;
        numSour += ((numberOfSources[0] & 255) * 256);
        
        int j = 0;
        
        if(numSour>0){
            sourceAddress = new byte[numSour][4];

            for(int i =0 ;i<numSour;i++){
                sourceAddress[i][0] = grupo[8+j];
                sourceAddress[i][1] = grupo[9+j];
                sourceAddress[i][2] = grupo[10+j];
                sourceAddress[i][3] = grupo[11+j];
                j+=4;
            }
        }
        int aDatLen = auxDataLen & 255;
        if(aDatLen>0){
            auxiliaryData = Arrays.copyOfRange(grupo,8+j,grupo.length);
        }
    }
    private String tosrtRecordType(){
        return (recordType&255)+"";
    }
    private String tostrAuxDataLen(){
        return (auxDataLen&255)+"";
    }
    private String tostrNumberOfSources(){
        int numSour = numberOfSources[1] & 255;
        numSour += ((numberOfSources[0] & 255) * 256);
        return numSour+"";
    }
    private String tostrMulticastAddress(){
        int mult1 = multicastAddress[0] & 255;
        int mult2 = multicastAddress[1] & 255;
        int mult3 = multicastAddress[2] & 255;
        int mult4 = multicastAddress[3] & 255;
        
        return mult1+"."+mult2+"."+mult3+"."+mult4;
    }
    private String tostrSourceAddress(){
        int numSour = numberOfSources[1] & 255;
        numSour += ((numberOfSources[0] & 255) * 256);
        
        int sou1;
        int sou2;
        int sou3;
        int sou4;
        
        StringBuilder sources = new StringBuilder(15000);
        for(int i =0 ;i<numSour;i++){
            sou1 = sourceAddress[i][0] & 255;
            sou2 = sourceAddress[i][1] & 255;
            sou3 = sourceAddress[i][2] & 255;
            sou4 = sourceAddress[i][3] & 255;
            
            sources.append("\t\t").append(sou1).append(".").append(sou2).append(".").append(sou3).append(".").append(sou4).append("\n");
        }
        return sourceAddress==null?"\t\t-No data-\n":sources.toString();
    }
    private String tostrAuxiliaryData(){
        return auxiliaryData==null?"-No data-":ByteArrays.toHexString(auxiliaryData, " ");
    }
    
    @Override
    public String toString(){
        StringBuilder grReco = new StringBuilder(20000);
        grReco.append("\t\t.....\n");
        grReco.append("\t\tRecord type: ").append(this.tosrtRecordType()).append("\n");
        grReco.append("\t\tAuxiliary data length: ").append(this.tostrAuxDataLen()).append("\n");
        grReco.append("\t\tNumber of sources: ").append(this.tostrNumberOfSources()).append("\n");
        grReco.append("\t\tMuticast Address: ").append(this.tostrMulticastAddress()).append("\n");
        grReco.append("\t\tSources:\n").append(this.tostrSourceAddress());
        grReco.append("\t\tAuxiliary data: ").append(this.tostrAuxiliaryData()).append("\n");
        grReco.append("\t\t.....\n");
        
        return grReco.toString();
    }
}
