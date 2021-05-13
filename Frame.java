
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.SpinnerNumberModel;
import javax.swing.table.DefaultTableModel;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author lalex
 */
public class Frame extends javax.swing.JFrame {

    /**
     * Creates new form Frame
     */
    public Frame() {
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jToolBar1 = new javax.swing.JToolBar();
        interfazSelec = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        jTextField1 = new javax.swing.JTextField();
        opciones = new javax.swing.JComboBox<>();
        jLabel4 = new javax.swing.JLabel();
        tiempoSpin = new javax.swing.JSpinner(new SpinnerNumberModel(5,0,3600,1));
        jLabel3 = new javax.swing.JLabel();
        cantidadSpin = new javax.swing.JSpinner(new SpinnerNumberModel(1,0,20000,1));
        iniPause = new javax.swing.JToggleButton();
        estatus = new javax.swing.JLabel();
        ejemplo = new javax.swing.JButton();
        jScrollPane2 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();
        scrollAnalisis = new javax.swing.JScrollPane();
        analisis = new javax.swing.JTextArea();
        jTextField2 = new javax.swing.JTextField();
        jButton1 = new javax.swing.JButton();
        jBaraComun = new javax.swing.JMenuBar();
        file = new javax.swing.JMenu();
        abrirArchivo = new javax.swing.JMenuItem();
        cerrarArchivo = new javax.swing.JMenuItem();
        guardaCap = new javax.swing.JMenuItem();
        aboutUs = new javax.swing.JMenu();
        equipo = new javax.swing.JMenuItem();
        info = new javax.swing.JMenuItem();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Super Sniffer osi osi");
        setLocation(new java.awt.Point(0, 0));
        setMinimumSize(new java.awt.Dimension(800, 500));

        jPanel1.setLayout(null);
        jPanel1.setBackground(new java.awt.Color(204, 204, 255));

        jLabel1.setBackground(new java.awt.Color(153, 153, 255));
        jLabel1.setText("Paquetes Capturados");
        jLabel1.setOpaque(true);

        jToolBar1.setBackground(new java.awt.Color(204, 255, 255));
        jToolBar1.setBorder(null);
        jToolBar1.setFloatable(false);
        jToolBar1.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
        jToolBar1.setMinimumSize(new java.awt.Dimension(760, 50));
        jToolBar1.setPreferredSize(new java.awt.Dimension(760, 50));

        interfazSelec.setBackground(new java.awt.Color(255, 204, 204));
        interfazSelec.setText("Interfaz");
        interfazSelec.setFocusable(false);
        interfazSelec.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        interfazSelec.setMaximumSize(new java.awt.Dimension(50, 40));
        interfazSelec.setMinimumSize(new java.awt.Dimension(50, 40));
        interfazSelec.setPreferredSize(new java.awt.Dimension(50, 40));
        interfazSelec.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        interfazSelec.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                interfazSelecActionPerformed(evt);
            }
        });
        jToolBar1.add(interfazSelec);
        interfazSelec.setOpaque(true);

        jLabel2.setText("  Filtro:  ");
        jToolBar1.add(jLabel2);

        jTextField1.setPreferredSize(new java.awt.Dimension(200, 30));
        jToolBar1.add(jTextField1);

        opciones.setMaximumRowCount(4);
        opciones.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "--Opciones--", "Tiempo", "Cantidad", "Sin limite" }));
        opciones.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                opcionesActionPerformed(evt);
            }
        });
        jToolBar1.add(opciones);

        jLabel4.setText("  Tiempo (s)  ");
        jToolBar1.add(jLabel4);

        tiempoSpin.setEnabled(false);
        tiempoSpin.setPreferredSize(new java.awt.Dimension(100, 30));
        jToolBar1.add(tiempoSpin);

        jLabel3.setText("  No.Captura  ");
        jToolBar1.add(jLabel3);

        cantidadSpin.setEnabled(false);
        cantidadSpin.setMinimumSize(new java.awt.Dimension(50, 20));
        cantidadSpin.setPreferredSize(new java.awt.Dimension(100, 30));
        jToolBar1.add(cantidadSpin);

        iniPause.setBackground(new java.awt.Color(102, 255, 102));
        iniPause.setText("Inicia");
        iniPause.setEnabled(false);
        iniPause.setFocusable(false);
        iniPause.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        iniPause.setMaximumSize(new java.awt.Dimension(50, 50));
        iniPause.setMinimumSize(new java.awt.Dimension(50, 40));
        iniPause.setOpaque(true);
        iniPause.setPreferredSize(new java.awt.Dimension(50, 40));
        iniPause.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        iniPause.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                iniPauseActionPerformed(evt);
            }
        });
        jToolBar1.add(iniPause);

        jToolBar1.setOpaque(true);

        estatus.setBackground(new java.awt.Color(255, 153, 153));
        estatus.setHorizontalAlignment(javax.swing.SwingConstants.RIGHT);
        estatus.setText("Escuchando...");
        estatus.setEnabled(true);
        estatus.setOpaque(true);

        ejemplo.setText("Ejemplo");
        ejemplo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                muestraEjemplo(evt);
            }
        });

        jTable1.setBackground(new java.awt.Color(255, 255, 153));
        jTable1.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jTable1.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Id", "Mac Destino", "Mac Origen", "Tipo", "Tiempo"
            }
        ) {
            boolean[] canEdit = new boolean [] {
                false, false, false, false, false
            };

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        jTable1.getTableHeader().setReorderingAllowed(false);
        jTable1.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                selecPaquete(evt);
            }
        });
        jScrollPane2.setViewportView(jTable1);
        if (jTable1.getColumnModel().getColumnCount() > 0) {
            jTable1.getColumnModel().getColumn(0).setResizable(false);
            jTable1.getColumnModel().getColumn(1).setResizable(false);
            jTable1.getColumnModel().getColumn(2).setResizable(false);
            jTable1.getColumnModel().getColumn(3).setResizable(false);
            jTable1.getColumnModel().getColumn(4).setResizable(false);
        }

        analisis.setEditable(false);
        analisis.setBackground(new java.awt.Color(153, 255, 153));
        analisis.setColumns(20);
        analisis.setRows(5);
        analisis.setText("Analisis de paquetes...");
        scrollAnalisis.setViewportView(analisis);

        jTextField2.setEditable(false);
        jTextField2.setBackground(new java.awt.Color(255, 255, 204));
        jTextField2.setText("Archivo de captura abierto...");
        jTextField2.setEnabled(false);

        jButton1.setText("jButton1");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cerrarElHandle(evt);
            }
        });

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jToolBar1, javax.swing.GroupLayout.DEFAULT_SIZE, 800, Short.MAX_VALUE)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(scrollAnalisis)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel1Layout.createSequentialGroup()
                        .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 125, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(27, 27, 27)
                        .addComponent(jTextField2, javax.swing.GroupLayout.PREFERRED_SIZE, 204, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(ejemplo)
                        .addGap(18, 18, 18)
                        .addComponent(jButton1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(estatus, javax.swing.GroupLayout.PREFERRED_SIZE, 131, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(8, 8, 8))
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.Alignment.LEADING))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addComponent(jToolBar1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(estatus, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jTextField2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(ejemplo)
                    .addComponent(jButton1))
                .addGap(18, 18, 18)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 200, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(scrollAnalisis, javax.swing.GroupLayout.PREFERRED_SIZE, 169, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        estatus.setVisible(false);

        file.setText("File");
        file.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));

        abrirArchivo.setText("Abrir Archivo");
        abrirArchivo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                OpenFile(evt);
            }
        });
        file.add(abrirArchivo);

        cerrarArchivo.setText("Cerrar Archivo");
        cerrarArchivo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cerrarArchivoActionPerformed(evt);
            }
        });
        file.add(cerrarArchivo);

        guardaCap.setText("Guardar Captura");
        guardaCap.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                guardaCapActionPerformed(evt);
            }
        });
        file.add(guardaCap);

        jBaraComun.add(file);

        aboutUs.setText("About");

        equipo.setText("Equipo");
        equipo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                equipoInfo(evt);
            }
        });
        aboutUs.add(equipo);

        info.setText("Info");
        info.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                infoApp(evt);
            }
        });
        aboutUs.add(info);

        jBaraComun.add(aboutUs);

        setJMenuBar(jBaraComun);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents
    
    
    /***********************************************
     ***********************************************
     * 
        EVENTOS PARA LOS BOTONES, LA TABLA, ETC...
     * 
     ***********************************************
    ***********************************************/
    
    /*Abre el explorador de archivos para abrir uno*/
    private void OpenFile(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_OpenFile
        /*JOptionPane.showMessageDialog(this,
            "Abre y muestra un archivo",
            "Abrir archivo",
            JOptionPane.INFORMATION_MESSAGE);*/
        JFileChooser selectorArch = new JFileChooser();
        int respuesta = selectorArch.showOpenDialog(this);
        if(respuesta == JFileChooser.APPROVE_OPTION){
            jTextField2.setText(selectorArch.getSelectedFile().getAbsolutePath());
            jTextField2.setEnabled(true);
        }        
    }//GEN-LAST:event_OpenFile
    
    /*Muestra los integrantes del equipo*/
    private void equipoInfo(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_equipoInfo
        JOptionPane.showMessageDialog(this,
            "Equipo:\n- Yo\n- Uriel\n- Jose\n- David",
            "Info del equipo",
            JOptionPane.INFORMATION_MESSAGE);// TODO add your handling code here:
    }//GEN-LAST:event_equipoInfo
    
    /*Guarda un archivo*/
    private void guardaCapActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_guardaCapActionPerformed
        /*JOptionPane.showMessageDialog(this,
            "Guarda los paquetes capturados en un\n Archivo .pcap",
            "Guarda captura",
            JOptionPane.INFORMATION_MESSAGE);*/
        JFileChooser selectorArch = new JFileChooser();
        int respuesta = selectorArch.showSaveDialog(this);
        /*Falta chechar que no se este escuchando al momento de guardar*/
        if(respuesta == JFileChooser.APPROVE_OPTION){
            jTextField2.setText(selectorArch.getSelectedFile().getAbsolutePath());
            jTextField2.setEnabled(true);
        }               
    }//GEN-LAST:event_guardaCapActionPerformed
    
    /*Despliega las opciones para capturar paquetes por tiempo, por numero
        o Sin limite y hasta que se detenga con el boton */
    private void opcionesActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_opcionesActionPerformed
        /*Borra --Opciones-- cuando no se necesita*/
        if((String)opciones.getItemAt(0)=="--Opciones--")
                opciones.removeItemAt(0);
        
        if((String)opciones.getSelectedItem()=="Tiempo"){
            iniPause.setEnabled(true);
            tiempoSpin.setEnabled(true);
            cantidadSpin.setEnabled(false);            
        }
        else if((String)opciones.getSelectedItem()=="Cantidad"){
            iniPause.setEnabled(true);
            tiempoSpin.setEnabled(false);
            cantidadSpin.setEnabled(true);            
        }
        else if((String)opciones.getSelectedItem()=="Sin limite"){
            iniPause.setEnabled(true);
            tiempoSpin.setEnabled(false);
            cantidadSpin.setEnabled(false);            
        }
        else{
            iniPause.setEnabled(false);
            tiempoSpin.setEnabled(false);
            cantidadSpin.setEnabled(false);
        }
    }//GEN-LAST:event_opcionesActionPerformed
    
    /*Inicia y pausa la captura de paquetes*/
    private void iniPauseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_iniPauseActionPerformed
       
        if(iniPause.isSelected()){
            estatus.setVisible(true);
            estatus.setText("Escuchando...");
            estatus.setBackground(new java.awt.Color(102, 255, 102));//Verde
            
            iniPause.setText("Pausa");
            iniPause.setBackground(new java.awt.Color(255,153,153));//Rojo
            /*Aqui deberia de empezar a capturar paquetes*/
            
            try {
                sniffer.escuchaPaquetes(jTable1);//sniffer.start();
            } catch (PcapNativeException ex) {
                Logger.getLogger(Frame.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NotOpenException ex) {
                Logger.getLogger(Frame.class.getName()).log(Level.SEVERE, null, ex);
            }
            /*estatus.setText("Finalizado");
            estatus.setBackground(new java.awt.Color(51,204,255));//Azul
            iniPause.setText("Inicia");
            iniPause.setBackground(new java.awt.Color(102, 255, 102));
            iniPause.setSelected(false*/
            
        }
        else {
            estatus.setText("En pausa...");
            estatus.setBackground(new java.awt.Color(255,153,153));//Rojo
            iniPause.setText("Inicia");
            iniPause.setBackground(new java.awt.Color(102, 255, 102));//Verde
            /*Aqui se debria de detener la captura*/
        }
    }//GEN-LAST:event_iniPauseActionPerformed
      
    /*Cierra un archivo abierto*/
    private void cerrarArchivoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cerrarArchivoActionPerformed
        /*JOptionPane.showMessageDialog(this,
            "Cierra Archivo .pcap",
            "Cerrar archivo",
            JOptionPane.INFORMATION_MESSAGE);*/              
        jTextField2.setEnabled(false);
        analisis.setText("Analisis de paquetes...");
        jTable1.removeAll();
    }//GEN-LAST:event_cerrarArchivoActionPerformed
    
    /*Muestra la información de un paquete capturado que se muestra en la
        tabla*/
    private void selecPaquete(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_selecPaquete
        DefaultTableModel model = (DefaultTableModel)jTable1.getModel();// TODO add your handling code here:
        int i = jTable1.getSelectedRow();
        /*String aux = "ANALISIS DE LA TRAMA "+(i+1)+":\n"
                +"- MAC DESTINO: "+model.getValueAt(i, 1).toString() + "\n"
                +"- MAC ORIGEN: "+model.getValueAt(i, 2).toString() + "\n"
                +"- TIPO: "+model.getValueAt(i, 3).toString() + "\n"
                +"- TAMANO: "+model.getValueAt(i, 4).toString() + "\n"
                +"- MAC DESTINO: "+model.getValueAt(i, 1).toString() + "\n"
                +"- MAC ORIGEN: "+model.getValueAt(i, 2).toString() + "\n"
                +"- TIPO: "+model.getValueAt(i, 3).toString() + "\n"
                +"- TAMANO: "+model.getValueAt(i, 4).toString() + "\n"
                +"== TRAMA EN CRUDO==\n"
                +"00 00 00 00 00 00 00...";
        */
        
        analisis.setText(sniffer.analisisTrama(i));
        
    }//GEN-LAST:event_selecPaquete
    
    /*Informacion que se quiera mostrar de la aplicacion*/
    private void infoApp(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_infoApp
        JOptionPane.showMessageDialog(this,
            "Informacion de la aplicación",
            "Informacion",
            JOptionPane.INFORMATION_MESSAGE);
    }//GEN-LAST:event_infoApp
    
    /*Escoge la inferfaz para escuchar*/
    private void interfazSelecActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_interfazSelecActionPerformed
        JOptionPane.showMessageDialog(this,
            "Escoje tu interfaz",
            "Interfaz",
            JOptionPane.INFORMATION_MESSAGE);
        sniffer.setTable(jTable1);
        sniffer.setBotonInicio(iniPause);
        sniffer.setLabelEstatus(estatus);
        try {
            sniffer.selecInterfaz();
        } catch (PcapNativeException ex) {
            Logger.getLogger(Frame.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NotOpenException ex) {
            Logger.getLogger(Frame.class.getName()).log(Level.SEVERE, null, ex);
        }               
        
    }//GEN-LAST:event_interfazSelecActionPerformed

    /*Pone ejemplos en la tabla para checar como se veria*/
    private void muestraEjemplo(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_muestraEjemplo
        ArrayList<Paquete> listaPaquetes = new ArrayList<Paquete>(25);// TODO add your handling code here:
        listaPaquetes.add(new Paquete(0,"FF-FF-FF-FF-FF-FF","DD-DD-DD-DD-DD-DD","Arp","12 bytes"));
        listaPaquetes.add(new Paquete(1,"FF-FF-FF-FF-FF-FF","DD-DD-DD-DD-DD-DD","Arp","12 bytes"));
        listaPaquetes.add(new Paquete(2,"FF-FF-FF-FF-FF-FF","DD-DD-DD-DD-DD-DD","Arp","12 bytes"));
        listaPaquetes.add(new Paquete(3,"FF-FF-FF-FF-FF-FF","DD-DD-DD-DD-DD-DD","Arp","12 bytes"));
        listaPaquetes.add(new Paquete(4,"FF-FF-FF-FF-FF-FF","DD-DD-DD-DD-DD-DD","Arp","12 bytes"));
        listaPaquetes.add(new Paquete(5,"FF-FF-FF-FF-FF-FF","DD-DD-DD-DD-DD-DD","Arp","12 bytes"));
        listaPaquetes.add(new Paquete(6,"FF-FF-FF-FF-FF-FF","DD-DD-DD-DD-DD-DD","Arp","12 bytes"));
        listaPaquetes.add(new Paquete(7,"FF-FF-FF-FF-FF-FF","DD-DD-DD-DD-DD-DD","Arp","12 bytes"));
        listaPaquetes.add(new Paquete(8,"FF-FF-FF-FF-FF-FF","DD-DD-DD-DD-DD-DD","Arp","12 bytes"));
        listaPaquetes.add(new Paquete(9,"FF-FF-FF-FF-FF-FF","DD-DD-DD-DD-DD-DD","Arp","12 bytes"));
        listaPaquetes.add(new Paquete(10,"FF-FF-FF-FF-FF-FF","DD-DD-DD-DD-DD-DD","Arp","12 bytes"));
        listaPaquetes.add(new Paquete(11,"FF-FF-FF-FF-FF-FF","DD-DD-DD-DD-DD-DD","Arp","12 bytes"));

        DefaultTableModel model = (DefaultTableModel)jTable1.getModel();
        Object registro[] = new Object[5];
        for(int i = 0;i<listaPaquetes.size();i++){
            registro[0] = listaPaquetes.get(i).id;
            registro[1] = listaPaquetes.get(i).macDestino;
            registro[2] = listaPaquetes.get(i).macOrigen;
            registro[3] = listaPaquetes.get(i).tipo;
            registro[4] = listaPaquetes.get(i).tamano;
            model.addRow(registro);
        }
    }//GEN-LAST:event_muestraEjemplo

    private void cerrarElHandle(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cerrarElHandle
       
        try {
            sniffer.cierraHandle();
        } catch (PcapNativeException ex) {
            Logger.getLogger(Frame.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NotOpenException ex) {
            Logger.getLogger(Frame.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_cerrarElHandle

    /* PARA EJEMPLO DE COMO FUNCIONA LA TABLA*/
    class Paquete{
        int id=0;
        String macOrigen;
        String macDestino;
        String tipo;
        String tamano;

        public Paquete(int id,String macOrigen, String macDestino, String Tipo, String Tamano) {
            this.id = id;
            this.macOrigen = macOrigen;
            this.macDestino = macDestino;
            this.tipo = Tipo;
            this.tamano = Tamano;
        }                        
    }
    
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Frame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Frame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Frame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Frame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Frame().setVisible(true);
            }
        });
        
        /*Crea la ventana y la inicializa con los componentes*/
       /* Frame app = new Frame();
        app.setVisible(true);
        app.setLocationRelativeTo(null);*///Para que aparezca en medio la pantalla
        
        /*******************************/
        /* CREA EN SNIFFER  */
        sniffer = new GetNextRawPacket();
    } 

    /*Son los botones, etiquetas, tabla, etc*/
    private static GetNextRawPacket sniffer;     
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JMenu aboutUs;
    private javax.swing.JMenuItem abrirArchivo;
    private javax.swing.JTextArea analisis;
    private javax.swing.JSpinner cantidadSpin;
    private javax.swing.JMenuItem cerrarArchivo;
    private javax.swing.JButton ejemplo;
    private javax.swing.JMenuItem equipo;
    private javax.swing.JLabel estatus;
    private javax.swing.JMenu file;
    private javax.swing.JMenuItem guardaCap;
    private javax.swing.JMenuItem info;
    private javax.swing.JToggleButton iniPause;
    private javax.swing.JButton interfazSelec;
    private javax.swing.JMenuBar jBaraComun;
    private javax.swing.JButton jButton1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JTable jTable1;
    private javax.swing.JTextField jTextField1;
    private javax.swing.JTextField jTextField2;
    private javax.swing.JToolBar jToolBar1;
    private javax.swing.JComboBox<String> opciones;
    private javax.swing.JScrollPane scrollAnalisis;
    private javax.swing.JSpinner tiempoSpin;
    // End of variables declaration//GEN-END:variables
}