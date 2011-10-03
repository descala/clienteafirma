package es.gob.afirma.ui.principal;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.KeyEvent;

import javax.swing.AbstractListModel;
import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.SwingConstants;
import javax.swing.WindowConstants;

import es.gob.afirma.core.misc.Platform;
import es.gob.afirma.ui.utils.Constants;
import es.gob.afirma.ui.utils.GeneralConfig;
import es.gob.afirma.ui.utils.InfoLabel;
import es.gob.afirma.ui.utils.JAccessibilityDialogAdvisor;
import es.gob.afirma.ui.utils.Messages;

public class UserProfile extends JAccessibilityDialogAdvisor {

	private static final long serialVersionUID = 1L;
	
	@Override
	public int getMinimumRelation() {
		// TODO Auto-generated method stub
		return 9;
	}
    
    public static String currentUser;
    
    JList list = new JList();
       
	private int actualPositionX = -1;
	
	private int actualPositionY = -1;
	
	private int actualWidth = -1;
	
	private int actualHeight = -1;
	
	/**
	 * Posici�n X inicial de la ventana dependiendo de la resoluci�n de pantalla.
	 * @return int Posici�n X
	 */
	public int getInitialX() {
		Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize(); //329
		return (screenSize.width - 500) / 2 ;
	}
	
	/**
	 * Posici�n Y inicial de la ventana dependiendo del sistema operativo y de la
	 * resoluci�n de pantalla.
	 * @return int Posici�n Y
	 */
	public int getInitialY() {
		Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize(); //329
		if (Platform.getOS().equals(Platform.OS.MACOSX)){
			return (screenSize.height - 340) / 2;
		}else{
			return (screenSize.height - 320) / 2;
		}
	}
	
	public UserProfile() {
		super();
		initComponents();
		this.addComponentListener(new ComponentAdapter() {
		    public void componentResized(ComponentEvent e)
		    {
		    	resized(e);
		    }
		    public void componentMoved(ComponentEvent e)
		    {
		    	resized(e);
		    }
		});
	}
	
	/**
	 * Inicializacion de los componentes
	 */
	private void initComponents() {
		
		// Dimensiones de la ventana
		setBounds(this.getInitialX(), this.getInitialY(), Constants.INIT_WINDOW_INITIAL_WIDTH, Constants.INIT_WINDOW_INITIAL_HEIGHT);
		
		// Parametros ventana
		setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE); // NOI18N
		setTitle(Messages.getString("UserProfile.title")); // NOI18N
		getContentPane().setLayout(new BorderLayout(11, 7));
		setMinimumSize(getSize());

		// Icono de @firma
		setIconImage(new ImageIcon(getClass().getResource("/resources/images/afirma_ico.png")).getImage());
		
		this.setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
        
		c.fill = GridBagConstraints.BOTH;
        c.weightx = 1.0;
        c.insets = new Insets(5, 13, 5, 13);
        c.gridy = 0;
        
        // Logotipo de la aplicacion
        c.gridwidth = 3;
        JLabel logotipo = new JLabel();
		logotipo.setIcon(new ImageIcon(getClass().getResource("/resources/images/logo_cliente.png")));//$NON-NLS-1$
		logotipo.setHorizontalAlignment(SwingConstants.CENTER);
		add(logotipo, c);
		c.gridy = c.gridy + 1;
		c.gridwidth = 1;

		// Cuerpo del mensaje
		InfoLabel text = new InfoLabel("<p>"+Messages.getString("UserProfile.welcome")+"</p>"+"<p>"+Messages.getString("UserProfile.body1")+"</p>"+"<p>"+Messages.getString("UserProfile.body2")+"</p>"+"<p>"+Messages.getString("UserProfile.body3")+"</p>", false);
		config(text);
		
		add(text,c);
		c.gridy = c.gridy + 1;
		
        // Etiqueta de la lista de usuarios
		InfoLabel label = new InfoLabel(Messages.getString("UserProfile.list.label"), false);
		label.setDisplayedMnemonic(KeyEvent.VK_P);
		label.setLabelFor(list);
		config(label);
		
		add(label,c);
		c.gridy = c.gridy + 1;
		
		// Lista de usuarios
		int j;
		if (Main.preferences.get("users", "0").equals("0")){
			j=1;
		} else {
			j =Integer.parseInt(Main.preferences.get("users", "0"))+1; 
		}
		final String[] users = new String[j];
		final String[] userssss = new String[j];
		for (int i = 0;i<=Integer.parseInt(Main.preferences.get("users", "0"))-1;i++){
	        	userssss[i] = "user" + (i+1);
	        	
	        	users[i]=(Main.preferences.get(userssss[i], "error"));
	        	
	    }
		users[users.length-1] = Constants.defaultUser;
		final String[] strings = users;
		list.setModel(new AbstractListModel() {
			private static final long serialVersionUID = 1L;

				public int getSize() { 
					return strings.length; 
				}

				public Object getElementAt(int i) { 
					return strings[i]; 
				}
			});
		list.setSelectedIndex(strings.length-1);
		config(list);
		add(list,c);
		
		c.gridy = c.gridy + 1;
		c.insets = new Insets(5, 150, 5, 150);
		
		// Boton aceptar
		JButton aceptar = new JButton();
		aceptar.setText("Aceptar");
		aceptar.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				aceptarPerformed();
			}
		});
		config(aceptar);
		
		add(aceptar,c);
		c.gridy = c.gridy + 1;
	}
	
	/**
	 * Evento de redimensionado. Almacena los valores actuales de posicion y 
	 * tama�o de la ventana.
	 * 
	 */
	public void resized(ComponentEvent e) {
		Dimension screenSize = this.getSize();
	    screenSize = Toolkit.getDefaultToolkit().getScreenSize();
		if (this.getWidth()!=(int)screenSize.getWidth() && this.getHeight()!=(int)screenSize.getHeight()-35){
			actualPositionX = this.getX();
			actualPositionY = this.getY();
			actualWidth = this.getWidth();
			actualHeight = this.getHeight();
		}
	}
	/**
	 * Muestra la ventana de la aplicaci�n
	 */
	public void main() {	
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				setVisible(true);
			}
		});	
	}
    
    /**
     * 
     */
    public void aceptarPerformed(){
    	if (list.getSelectedValue()==null){
    		currentUser = Constants.defaultUser;
    	} else {
    		currentUser = list.getSelectedValue().toString();
    	}
    	GeneralConfig.loadConfig(GeneralConfig.getConfig());
    	new PrincipalGUI().main();
    	dispose();
    	
		
    }
    
    /**
     * Configuracion de accesibilidad por defecto de la pantalla.
     * Marcado de elementos con foco. 
     * @param component
     */
    private void config(JComponent component){
    	if (component instanceof JLabel){
			final JLabel label = (JLabel) component;
			label.addFocusListener(new FocusListener() {
				public void focusLost(FocusEvent e) {
					label.setBorder(BorderFactory.createEmptyBorder());
				}
				public void focusGained(FocusEvent e) {
					label.setBorder(BorderFactory.createLineBorder(Color.BLACK, 2));
				}
			});
			
		}
    	if (component instanceof JList){
			final JList list = (JList) component;
			list.addFocusListener(new FocusListener() {
				public void focusLost(FocusEvent e) {
					list.setBorder(BorderFactory.createEmptyBorder());
				}
				public void focusGained(FocusEvent e) {
					list.setBorder(BorderFactory.createLineBorder(Color.BLACK, 2));
				}
			});
		}
    	if (component instanceof JButton){
			final JButton button = (JButton) component;
			button.addFocusListener(new FocusListener() {
				public void focusLost(FocusEvent e) {
					button.setFont(new Font(button.getFont().getName(), button.getFont().getStyle(), button.getFont().getSize()-5));
				}		
				public void focusGained(FocusEvent e) {
					button.setFont(new Font(button.getFont().getName(), button.getFont().getStyle(), button.getFont().getSize()+5));
				}
			});
		}
    }
	
}
