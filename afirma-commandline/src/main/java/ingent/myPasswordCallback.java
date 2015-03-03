package ingent;

import javax.security.auth.callback.*;

  
public class myPasswordCallback extends  PasswordCallback{

	private String password;

	public myPasswordCallback(String password) {
		super("test",false);
		this.password = password;		
	}

	@Override
	public char[] getPassword() {
		return password.toCharArray();
	}
}
