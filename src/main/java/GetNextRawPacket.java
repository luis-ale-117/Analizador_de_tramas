
import com.sun.jna.Platform;
import java.io.IOException;
import java.util.ArrayList;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.JToggleButton;
import javax.swing.table.DefaultTableModel;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
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
public class GetNextRawPacket /*extends Thread*/ {

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
  
  public GetNextRawPacket() {
      filter = "";
      num = 0;
      nif = null;
      handle = null;
      paquetesCapturados = new ArrayList<Paquete>(50);
      tab = null;
  }

  public /*static*/ void selecInterfaz(/*String[] args*/) throws PcapNativeException, NotOpenException {
    //String filter = args.length != 0 ? args[0] : "";
    filter = "";
    
    System.out.println(COUNT_KEY + ": " + COUNT);
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
    System.out.println(BUFFER_SIZE_KEY + ": " + BUFFER_SIZE);
    System.out.println(NIF_NAME_KEY + ": " + NIF_NAME);
    System.out.println("\n");

    //PcapNetworkInterface nif;
    
    if (NIF_NAME != null) {
      nif = Pcaps.getDevByName(NIF_NAME);
    } else {
      try {
        nif = new NifSelector().selectNetworkInterface();
      } catch (IOException e) {
        e.printStackTrace();
        return;
      }

      if (nif == null) {
        return;
      }
    }

    System.out.println(nif.getName() + " (" + nif.getDescription() + ")");
    for (PcapAddress addr : nif.getAddresses()) {
      if (addr.getAddress() != null) {
        System.out.println("IP address: " + addr.getAddress());
      }
    }
    System.out.println("");

    /*PcapHandle*/ handle =
        new PcapHandle.Builder(nif.getName())
            .snaplen(SNAPLEN)
            .promiscuousMode(PromiscuousMode.PROMISCUOUS)
            .timeoutMillis(READ_TIMEOUT)
            .bufferSize(BUFFER_SIZE)
            .build();

    

    
  }
  
  public void escuchaPaquetes(JTable tablaPaquetes,String filtro,int cantidad) throws PcapNativeException, NotOpenException{
      filter =filtro;
      handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
      /*int*/ num = 0;
    Object registro[]= new Object[5];
    DefaultTableModel model = (DefaultTableModel)tablaPaquetes.getModel();
    String horaCaptura;
    int index;
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
        if (num >= cantidad/*COUNT*/ /*|| tiempo>5000*/ /*num cap*/) {
          break;
        }
      }
    }

    PcapStat ps = handle.getStats();
    System.out.println("ps_recv: " + ps.getNumPacketsReceived());
    System.out.println("ps_drop: " + ps.getNumPacketsDropped());
    System.out.println("ps_ifdrop: " + ps.getNumPacketsDroppedByIf());
    if (Platform.isWindows()) {
      System.out.println("bs_capt: " + ps.getNumPacketsCaptured());
    }
    //handle.close();
    labelEstatus.setText("Finalizado");
      labelEstatus.setBackground(new java.awt.Color(51,204,255));//Azul
      botonInicio.setText("Inicia");
      botonInicio.setBackground(new java.awt.Color(102, 255, 102));
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
  /*
  @Override
  public void run(){
      try {
          this.escuchaPaquetes(tab);
      } catch (PcapNativeException ex) {
          Logger.getLogger(GetNextRawPacket.class.getName()).log(Level.SEVERE, null, ex);
      } catch (NotOpenException ex) {
          Logger.getLogger(GetNextRawPacket.class.getName()).log(Level.SEVERE, null, ex);
      }
      labelEstatus.setText("Finalizado");
      labelEstatus.setBackground(new java.awt.Color(51,204,255));//Azul
      botonInicio.setText("Inicia");
      botonInicio.setBackground(new java.awt.Color(102, 255, 102));
      botonInicio.setSelected(false);
  }*/
  
}