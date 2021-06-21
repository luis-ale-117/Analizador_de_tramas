
import com.sun.jna.Platform;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.JToggleButton;
import javax.swing.table.DefaultTableModel;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.NifSelector;

/*
    GetNextRawPacket
    CLASE QUE NOS PERMITE CAPTURAR PAQUETES
    ESCOGIENDO CIERTA INTERFAZ
*/

@SuppressWarnings("javadoc")
public class GetNextRawPacket {

  private static final String COUNT_KEY = GetNextRawPacket.class.getName() + ".count";
  private static final int COUNT = Integer.getInteger(COUNT_KEY, 20);/*Cuantas tramas captura*/
  
  private static final String READ_TIMEOUT_KEY = GetNextRawPacket.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = GetNextRawPacket.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  private static final String BUFFER_SIZE_KEY = GetNextRawPacket.class.getName() + ".bufferSize";
  private static final int BUFFER_SIZE =
      Integer.getInteger(BUFFER_SIZE_KEY, 1 * 1024 * 1024); // [bytes]

  private static final String NIF_NAME_KEY = GetNextRawPacket.class.getName() + ".nifName";
  private static final String NIF_NAME = System.getProperty(NIF_NAME_KEY);
  
  /*****************************************/
  /*Varibales de la clase para que funcione*/
  /*****************************************/
  private String filter;
  private PcapNetworkInterface nif;
  private PcapHandle handle;
  private int num;
  private ArrayList<Paquete> paquetesCapturados;
  private JTable tab;
  private JToggleButton botonInicio;
  private JLabel labelEstatus;
  private List<PcapNetworkInterface> allDevs;//Interfaces de Red
  
  public GetNextRawPacket() {
      filter = "";
      num = 0;
      nif = null;
      handle = null;
      paquetesCapturados = new ArrayList<Paquete>(500);
      tab = null;
      allDevs = null;
  }

  public void selecInterfaz() throws PcapNativeException, NotOpenException {
        /********************************************/
        /*PARA OBTENER INFO DE LAS INTERFACES DE RED*/
        /********************************************/
        
        try {
            allDevs = Pcaps.findAllDevs();
        } catch (PcapNativeException e) {
            try {
                throw new IOException(e.getMessage());
            } catch (IOException ex) {
                Logger.getLogger(GetNextRawPacket.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        if (allDevs == null || allDevs.isEmpty()) {
            try {
                throw new IOException("No NIF to capture.");
            } catch (IOException ex) {
                Logger.getLogger(GetNextRawPacket.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        /*showNifList => Obten en String las interfaces */
        StringBuilder sb = new StringBuilder(200);
        String[] interfacesStr = new String[allDevs.size()];
        
        int nifIdx = 0;
        for (PcapNetworkInterface nif : allDevs) {
            sb.append("[").append(nifIdx).append("]: ").append(nif.getName());
            if (nif.getDescription() != null) {
                sb.append(" :Description: ").append(nif.getDescription());
            }
            interfacesStr[nifIdx] = sb.toString();
            sb.delete(0, sb.length());
            nifIdx++;
        }
        /*Hasta aqui se muestran todas las interfaces*/
                                                
        /*LO MINIMO PARA UN MENSAJE DE SELECCION CON OPCIONES*/

        String entrada = (String) JOptionPane.showInputDialog(null, "Escoge una interfaz de red para iniciar la captura",
                "Seleccion de interfaz" , JOptionPane.QUESTION_MESSAGE,null,interfacesStr,interfacesStr[0]);
        if (entrada==null){
            return;
        }
        /*doSelect => Selecciona la interfaz*/

        int i;
        int indiceNif=0;
        for(i=0;i<allDevs.size();i++){
            if(interfacesStr[i]==entrada)
                indiceNif = i;
        }
        handle =
            new PcapHandle.Builder(allDevs.get(indiceNif).getName())
                .snaplen(SNAPLEN)
                .promiscuousMode(PromiscuousMode.PROMISCUOUS)
                .timeoutMillis(READ_TIMEOUT)
                .bufferSize(BUFFER_SIZE)
                .build();
 
  }
  
  public void inicializafiltro(String fil)throws PcapNativeException, NotOpenException{
      handle.setFilter(fil, BpfCompileMode.OPTIMIZE);
  }
  
  public void escuchaPaquetes(JTable tablaPaquetes,int cantidad,int tiempo, String opcionSeleccionada) throws PcapNativeException, NotOpenException{
    num = 0;
    Object registro[]= new Object[5];
    DefaultTableModel model = (DefaultTableModel)tablaPaquetes.getModel();
    String horaCaptura;
    int index;
    int tiempoCaptura = tiempo*1000;//Llega en milisegundos
    long tiempoInicio=System.currentTimeMillis();
    long tiempoActual;
    
    while (true) {
      byte[] packet = handle.getNextRawPacket();
      if (packet == null) {
        continue;
      } else {       
        /*En la GUI*/
        horaCaptura = handle.getTimestamp().toString();        
        paquetesCapturados.add(new Paquete(packet, horaCaptura,paquetesCapturados.size()));
        index = paquetesCapturados.size()-1;
        
        registro[0] = paquetesCapturados.size()-1;
        registro[1] = paquetesCapturados.get(index).tostrMacDestino();
        registro[2] = paquetesCapturados.get(index).tostrMacOrigen();
        registro[3] = paquetesCapturados.get(index).tostrTipoLong();
        registro[4] = paquetesCapturados.get(index).tostrHora();
        model.addRow(registro);        
        num++;
        if(opcionSeleccionada=="Cantidad"){
            if (num >= cantidad) {
                break;
            }        
        }else if(opcionSeleccionada=="Tiempo"){
            tiempoActual = System.currentTimeMillis();
            if((tiempoActual-tiempoInicio)>=tiempoCaptura){
                break;
            }
        }            
      }
    }

    
    //handle.close();
      labelEstatus.setText("Finalizado");
      labelEstatus.setBackground(new java.awt.Color(51,204,255));//Azul
      botonInicio.setText("Inicia");
      botonInicio.setBackground(new java.awt.Color(102, 255, 102));//Verde
      botonInicio.setSelected(false);
  }
  
  public void cierraHandle()throws PcapNativeException, NotOpenException{
      handle.close();
  }
  
  public String analisisTrama(int index){      
      return paquetesCapturados.get(index).toString();
  }
  public void setTable(JTable tablaPaquetes){
      tab = tablaPaquetes;
  }
  public void setBotonInicio(JToggleButton boton){
      botonInicio = boton;
  }
  public void setLabelEstatus(JLabel estatus){
      labelEstatus = estatus;
  }
  public ArrayList<Paquete> getPaquetes(){
      return paquetesCapturados;
  }
  public void clearArrayPaquetes(){
       paquetesCapturados.clear();
  }
  public PcapDumper createDumper(String nomArchivo){
      try {
          return handle.dumpOpen(nomArchivo);
      } catch (PcapNativeException ex) {
          Logger.getLogger(GetNextRawPacket.class.getName()).log(Level.SEVERE, null, ex);
          return null;
      } catch (NotOpenException ex) {
          Logger.getLogger(GetNextRawPacket.class.getName()).log(Level.SEVERE, null, ex);
          return null;
      }
  }
  
}