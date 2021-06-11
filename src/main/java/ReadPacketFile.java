import java.io.EOFException;
import java.util.ArrayList;
import java.util.concurrent.TimeoutException;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

@SuppressWarnings("javadoc")
public class ReadPacketFile {
  
  private String locacion="";
  private ArrayList<Paquete> paquetesCapturados;
    
  ReadPacketFile() {
      locacion="";
      paquetesCapturados = new ArrayList<Paquete>(50);
  }

  public void leerArchivo(JTable tablaPaquetes, String loc) throws PcapNativeException, NotOpenException {
    PcapHandle handle;
    Object registro[]= new Object[5];
    DefaultTableModel model = (DefaultTableModel)tablaPaquetes.getModel();
    String horaCaptura;
    int index;
    try {
      handle = Pcaps.openOffline(loc, TimestampPrecision.NANO);
    } catch (PcapNativeException e) {
      handle = Pcaps.openOffline(loc);
    }

    while(true){
      try {
        byte[] packet = handle.getNextRawPacket();
        if(packet==null){
            break;
        }
        
        horaCaptura = handle.getTimestamp().toString();        
        paquetesCapturados.add(new Paquete(packet, horaCaptura,paquetesCapturados.size()));
        index = paquetesCapturados.size()-1;
        
        registro[0] = paquetesCapturados.size()-1;
        registro[1] = paquetesCapturados.get(index).tostrMacDestino();
        registro[2] = paquetesCapturados.get(index).tostrMacOrigen();
        registro[3] = paquetesCapturados.get(index).tostrTipoLong();
        registro[4] = paquetesCapturados.get(index).tostrHora();
        model.addRow(registro);       
        
      }catch(Exception e){
          e.printStackTrace();
      } 
    }
    handle.close();
  }
   public String analisisTrama(int index){      
      return paquetesCapturados.get(index).toString();
  }
}