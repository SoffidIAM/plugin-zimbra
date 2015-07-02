// Copyright (c) 2000 Govern  de les Illes Balears
package com.soffid.iam.agent.zimbra;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.AttributeDirection;
import es.caib.seycon.ng.comu.AttributeMapping;
import es.caib.seycon.ng.comu.DadaUsuari;
import es.caib.seycon.ng.comu.LlistaCorreu;
import es.caib.seycon.ng.comu.ObjectMapping;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.comu.UserAccount;
import es.caib.seycon.ng.comu.Usuari;
//import es.caib.seycon.InternalErrorException;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.remote.RemoteServiceLocator;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.engine.extobj.AccountExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ObjectTranslator;
import es.caib.seycon.ng.sync.engine.extobj.UserExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMgr;
import es.caib.seycon.ng.sync.intf.MailAliasMgr;
import es.caib.seycon.ng.sync.intf.ReconcileMgr2;
import es.caib.seycon.ng.sync.intf.UserMgr;
import es.caib.seycon.util.TimedOutException;
import es.caib.seycon.util.TimedProcess;

/**
 * Agente to manage Zarafa server
 * <P>
 * 
 */

public class CustomizableZimbraAgent extends Agent implements UserMgr, MailAliasMgr,
		ReconcileMgr2, ExtensibleObjectMgr {
	/** zarfa-admin program */
	final static int TIMEOUT = 30000;
	private String zimbraAdmin;
	private String zimbraMailbox;
	boolean createProfile = false;
	private String fullNameExpression = null;
	private Collection<ExtensibleObjectMapping> objectMappings;
	private ObjectTranslator translator;
	public boolean deleteAccounts = false;
	HashSet<String> mailDomains;

	/**
	 * Constructor
	 * 
	 * @param params
	 *            vector con parámetros de configuración: <LI>0 = usuario</LI>
	 *            <LI>1 = contraseña oracle</LI> <LI>2 = cadena de conexión a la
	 *            base de datos</LI> <LI>3 = contraseña con la que se protegerán
	 *            los roles</LI>
	 */
	public CustomizableZimbraAgent() throws java.rmi.RemoteException {
		super();
	}

	/**
	 * Inicializar el agente.
	 */
	public void init() throws InternalErrorException {
		zimbraAdmin = getDispatcher().getParam0();
		if (zimbraAdmin == null || zimbraAdmin.length() == 0) {
			zimbraAdmin = "/opt/zimbra/zmprov";
		}
		zimbraMailbox = getDispatcher().getParam1();
		if (zimbraMailbox == null || zimbraMailbox.length() == 0) {
			zimbraMailbox = "/opt/zimbra/zmmailbox";
		}
		String s = getDispatcher().getParam2();
		if (s != null && s.equals("true")) {
			createProfile = true;
		}
		s = getDispatcher().getParam3();
		if (s != null && s.equals("true")) {
			deleteAccounts = true;
		}
		
		try {
			mailDomains = getMailDomains ();
		} catch (Exception e) {
			throw new InternalErrorException("Error getting mail domains", e);
		}
		log.info("Starting Zimbra Agent {}", getDispatcher().getCodi(), null);
	}

	private HashSet<String> getMailDomains() throws IOException, TimedOutException {
		TimedProcess p = new TimedProcess(TIMEOUT * 2);
		if (p.exec(new String[] { zimbraAdmin, "-l", "getAllDomains" }) == 0) {
			HashSet<String> hs = new HashSet<String>();
			for (String s: p.getOutput().split("[ ,\n]+") )
				hs.add(s);
			return hs;
		} else {
			throw new IOException("Error executing " + zimbraAdmin
						+ " -l getAllDomains:\n" + p.getOutput()+p.getError());
		}
	}

	private boolean existsZimbraUser(String name) throws IOException,
			TimedOutException {
		TimedProcess p = new TimedProcess(TIMEOUT * 2);
		if (p.exec(new String[] { zimbraAdmin, "-l", "getAccount", name, "uid" }) == 0) {
			return true;
		} else {
			if (p.getError().indexOf("account.NO_SUCH_ACCOUNT") >= 0)
				return false;
			else
				throw new IOException("Error executing " + zimbraAdmin
						+ " -l getAccount " + name + " :\n" + p.getOutput()+p.getError());
		}
	}

	private String concat(List<String> params) {
		StringBuffer b = new StringBuffer();
		for (String s : params) {
			if (b.length() > 0)
				b.append(' ');
			b.append(s);
		}
		return b.toString();
	}

	/**
	 * Actualizar los datos del usuario. Crea el usuario en la base de datos y
	 * le asigna una contraseña aleatoria. <BR>
	 * Da de alta los roles<BR>
	 * Le asigna los roles oportuno.<BR>
	 * Le retira los no necesarios.
	 * 
	 * @param user
	 *            código de usuario
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public void updateUser(String account, Usuari usu)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		updateUser (account, usu, null);
	}
	
	public void updateUser(String account, Usuari usu, Password password)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {

		Account acc = getServer().getAccountInfo(account, getCodi());
		updateUser (acc, usu, password);
	}
	
	public void updateUser(Account acc, Usuari usu, Password password)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER))
				{
					UserExtensibleObject aeo = new UserExtensibleObject(acc, usu, getServer());
					if (translator.evalCondition(aeo, mapping))
					{
						ExtensibleObject zimbraObject = translator.generateObject(aeo, mapping);
						
						if (zimbraObject != null)
						{
							updateZimbraAccount(acc.getName(), zimbraObject, password);
						}
					}
					else
					{
						deleteZimbraAccount(acc.getName());
					}
				}
			}

		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error processing task", e);
		}
	}

	/**
	 * Actualizar la contraseña del usuario. Asigna la contraseña si el usuario
	 * está activo y la contraseña no es temporal. En caso de contraseñas
	 * temporales, asigna un contraseña aleatoria.
	 * 
	 * @param user
	 *            código de usuario
	 * @param password
	 *            contraseña a asignar
	 * @param mustchange
	 *            es una contraseña temporal?
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public void updateUserPassword(String account, Usuari usuari,
			Password password, boolean mustchange)
			throws es.caib.seycon.ng.exception.InternalErrorException {
		try {
			if (!existsZimbraUser(account)) {
				if (usuari == null)
					updateUser(account, account, password);
				else
					updateUser(account, usuari, password);
			}
			processPasswordChange(account, password, mustchange, false);
			processPasswordChange(account, password, mustchange, true);
		} catch (RemoteException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (TimedOutException e) {
			throw new InternalErrorException("Error update password", e);
		}
	}

	private void processPasswordChange(String account, Password password,
			boolean mustchange, boolean ldap) throws IOException, TimedOutException,
			InternalErrorException {
		LinkedList<String> args = new LinkedList<String>();
		args.add(zimbraAdmin);
		if (ldap)
			args.add ("-l");
		args.add("setPassword");
		args.add(account);
		args.add(password.getPassword());
		TimedProcess p = new TimedProcess(TIMEOUT);
		if (p.exec(args.toArray(new String[args.size()])) != 0) {
			args.remove(4);
			throw new InternalErrorException("Error executing "
					+ concat(args) + ":\n" + p.getOutput()+p.getError());
		}

		args = new LinkedList<String>();
		args.add(zimbraAdmin);
		args.add("modifyAccount");
		args.add(account);
		args.add("zimbraPasswordMustChange");
		args.add(mustchange ? "TRUE" : "FALSE");
		args.add("zimbraPasswordLocked");
		args.add("FALSE");
		p = new TimedProcess(TIMEOUT);
		if (p.exec(args.toArray(new String[args.size()])) != 0) {
			throw new InternalErrorException("Error executing "
					+ concat(args) + ":\n" + p.getOutput()+p.getError());
		}
	}

	/**
	 * Validar contraseña.
	 * 
	 * @param user
	 *            código de usuario
	 * @param password
	 *            contraseña a asignar
	 * @return false
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public boolean validateUserPassword(String user, Password password)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		return false;
	}

	public void removeUser(String account) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		Account acc = getServer().getAccountInfo(account, getCodi());
		if (acc == null)
			deleteZimbraAccount(account);
		else
		{
			try {
				Usuari u = getServer().getUserInfo(account, getCodi());
				updateUser (acc, u, null);
			} catch (UnknownUserException e) {
				updateUser (acc, null);
			}
		}
	}

	private void deleteZimbraAccount(String account)
			throws InternalErrorException {
		try {
			// Comprobar si el usuario existe
			if (existsZimbraUser(account)) {
				if (deleteAccounts)
				{
					LinkedList<String> args = new LinkedList<String>();
					args.add(zimbraAdmin);
					args.add("-l");
					args.add("deleteAccount");
					args.add(account);
					TimedProcess p = new TimedProcess(TIMEOUT);
				    p.execNoWait (args.toArray(new String[args.size()]));
				    p.consumeOutput ();
				    p.consumeError ();
				    p.getInputStream().write("Y\n".getBytes());
				    p.getInputStream().flush();
					if (p.join() != 0) {
						throw new InternalErrorException("Error executing "
								+ concat(args) + ":\n" + p.getOutput()+p.getError());
					}
				} else {
					LinkedList<String> args = new LinkedList<String>();
					args.add(zimbraAdmin);
					args.add("-l");
					args.add("modifyAccount");
					args.add(account);
					args.add ("zimbraAccountStatus");
					args.add ("closed");
					args.add ("zimbraHideInGal");
					args.add ("TRUE");
					TimedProcess p = new TimedProcess(TIMEOUT);
				    p.execNoWait (args.toArray(new String[args.size()]));
				    p.consumeOutput ();
				    p.consumeError ();
				    p.getInputStream().write("Y\n".getBytes());
				    p.getInputStream().flush();
					if (p.join() != 0) {
						throw new InternalErrorException("Error executing "
								+ concat(args) + ":\n" + p.getOutput()+p.getError());
					}
				}
			}
		} catch (RemoteException e) {
			throw new InternalErrorException("Error deleting user", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error deleting user", e);
		} catch (TimedOutException e) {
			throw new InternalErrorException("Error deleting user", e);
		}
	}

	public void updateUser(Account acc, Password password)
			throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		try {
			for (ExtensibleObjectMapping mapping: objectMappings)
			{
				if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT))
				{
					AccountExtensibleObject aeo = new AccountExtensibleObject(acc, getServer());
					if (translator.evalCondition(aeo, mapping))
					{
						ExtensibleObject zimbraObject = translator.generateObject(aeo, mapping);
						
						if (zimbraObject != null)
						{
							updateZimbraAccount(acc.getName(), zimbraObject, password);
						}
					}
					else
						deleteZimbraAccount(acc.getName());
				}
			}

		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error processing task", e);
		}
	}

	public void updateUser(String account, String descripcio)
			throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		updateUser (account, descripcio, null);
	}
	
	private void updateUser(String account, String descripcio, Password password)
			throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {

		Account acc = getServer().getAccountInfo(account, getCodi());
		if (acc == null)
			deleteZimbraAccount(account);
		else
			updateUser (acc, password);
	
	}

	private void updateZimbraAccount(String account,
			ExtensibleObject zimbraObject, Password password) throws IOException,
			TimedOutException, InternalErrorException {
		// Comprobar si el usuario existe
		if (existsZimbraUser(account)) {
			LinkedList<String> args = new LinkedList<String>();
			args.add(zimbraAdmin);
			args.add("-l");
			args.add("modifyAccount");
			args.add(account);
			for (String att: zimbraObject.getAttributes())
			{
				args.add(att);
				Object v = zimbraObject.get(att);
				if (v == null)
					args.add ("");
				else
					args.add(v.toString());
			}
			TimedProcess p = new TimedProcess(TIMEOUT);
			if (p.exec(args.toArray(new String[args.size()])) != 0) {
				throw new InternalErrorException("Error executing "
						+ concat(args) + ":\n" + p.getOutput()+p.getError());
			}
		} else {
			if (password == null)
				password = getServer().getOrGenerateUserPassword(account,
					getCodi());
			LinkedList<String> args = new LinkedList<String>();
			args.add(zimbraAdmin);
			args.add("createAccount");
			args.add(account);
			args.add(password.getPassword());
			for (String att: zimbraObject.getAttributes())
			{
				args.add(att);
				Object v = zimbraObject.get(att);
				if (v == null)
					args.add ("");
				else
					args.add(v.toString());
			}
			TimedProcess p = new TimedProcess(TIMEOUT);
			if (p.exec(args.toArray(new String[args.size()])) != 0) {
				throw new InternalErrorException("Error executing "
						+ concat(args) + ":\n" + p.getOutput()+p.getError());
			}
		}
	}

	public List<String> getAccountsList() throws RemoteException,
			InternalErrorException {
		try {
			LinkedList<String> result = new LinkedList<String>();
			LinkedList<String> args = new LinkedList<String>();
			args.add(zimbraAdmin);
			args.add("-l");
			args.add("getAllAccounts");
			TimedProcess p = new TimedProcess(TIMEOUT * 20);
			if (p.exec(args.toArray(new String[args.size()])) != 0) {
				throw new InternalErrorException("Error executing "
						+ concat(args) + ":\n" + p.getOutput()+p.getError());
			}
			for (String s : p.getOutput().split("\n"))
				result.add(s);

			return result;
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error processing task", e);
		}
	}

	public List<String> getRolesList() throws RemoteException,
			InternalErrorException {
		return new LinkedList<String>();
	}

	public Rol getRoleFullInfo(String roleName) throws RemoteException,
			InternalErrorException {
		return null;
	}

	public void updateUserAlias(String userName, Usuari user)
			throws InternalErrorException {
		Collection<UserAccount> accounts = getServer().getUserAccounts(
				user.getId(), getCodi());
		if (accounts.size() == 1) {
			String oldName = accounts.iterator().next().getName();
			String newName = user.getNomCurt() + "@" + user.getDominiCorreu();
			if (!oldName.equals(newName)) {
				// UsuariService svc = new RemoteServiceLocator(
				// getServerName()).getUsuariService();
			}
		} else if (accounts.size() == 0) {

		}

	}

	private boolean existsZimbraList(String name) throws IOException,
			TimedOutException {
		TimedProcess p = new TimedProcess(TIMEOUT * 2);
		if (p.exec(new String[] { zimbraAdmin, "-l", "getDistributionList",
				name, "uid" }) == 0) {
			return true;
		} else {
			if (p.getError().indexOf("NO_SUCH_DISTRIBUTION_LIST") >= 0)
				return false;
			else
				throw new IOException("Error executing " + zimbraAdmin
						+ " -l getAccount " + name + " :\n" + p.getOutput()+p.getError());
		}
	}

	private String getAliasOwner(String name) throws IOException,
			TimedOutException {
		TimedProcess p = new TimedProcess(TIMEOUT * 2);
		String att = "zimbraMailDeliveryAddress";
		String prefix = att +": ";
		if (p.exec(new String[] { zimbraAdmin, "-l", "getAccount",
				name, att }) == 0) {
			for (String s : p.getOutput().split("\n")) {
				if (s.startsWith(prefix))
				{
					String owner = s.substring(prefix.length());
					
					if (! owner.equals(name))
						return owner;
				}
			}
			return null;
		} else {
			if (p.getError().indexOf("NO_SUCH_ACCOUNT") >= 0)
				return null;
			else
				throw new IOException("Error executing " + zimbraAdmin
						+ " -l getAccount " + name + " :\n" + p.getOutput()
						+ p.getError());
		}
	}

	private List<String> getZimbraAliasMembers(String name) throws IOException,
			TimedOutException {
		TimedProcess p = new TimedProcess(TIMEOUT * 2);
		if (p.exec(new String[] { zimbraAdmin, "-l", "getDistributionList",
				name, "zimbraMailForwardingAddress" }) != 0) {
			throw new IOException("Error executing " + zimbraAdmin
					+ " -l getAccount " + name + " :\n" + p.getOutput()+p.getError());
		} else {
			if (p.getError().indexOf("NO_SUCH_DISTRIBUTION_LIST") >= 0)
				return new LinkedList<String>();
			else {
				final String prefix = "zimbraMailForwardingAddress: ";
				LinkedList<String> list = new LinkedList<String>();
				for (String s : p.getOutput().split("\n")) {
					if (s.startsWith(prefix))
						list.add(s.substring(prefix.length()).toLowerCase());
				}
				return list;
			}
		}
	}

	public void removeUserAlias(String userKey) throws InternalErrorException {
	}

	String getUserEmail (String user) throws InternalErrorException, es.caib.seycon.ng.exception.UnknownUserException
	{
		Usuari u = getServer().getUserInfo(user, null);
		for (Account acc : getServer().getUserAccounts(u.getId(),
				getCodi()))
		{
			if (! acc.isDisabled())
				return acc.getName();
		}
		
		if (u.getDominiCorreu() != null)
			return u.getNomCurt()+"@"+u.getDominiCorreu();
		else
		{
			DadaUsuari email = getServer().getUserData(u.getId(), "EMAIL");
			if (email != null && email.getValorDada() != null)
				return email.getValorDada();
				
		}
		return null;
	}
	
	public void updateListAlias(LlistaCorreu llista)
			throws InternalErrorException {
		try {
			if (!  mailDomains.contains( llista.getCodiDomini()) )
				return;
			
			String name = llista.getNom() + "@" + llista.getCodiDomini();
			if (llista.getLlistaExterns() == null)
				llista.setLlistaExterns("");
			if (llista.getLlistaLlistes() == null)
				llista.setLlistaLlistes("");
			if (llista.getLlistaUsuaris() == null)
				llista.setLlistaUsuaris("");
			String users = getUsersList(llista);
			if (users == null)
				users = "";
			if (llista.getLlistaExterns().trim().length() == 0 &&
					llista.getLlistaLlistes().trim().length() == 0 &&
					users.trim().length() == 0 )
			{
				removeListAlias(llista.getNom(), llista.getCodiDomini());
				return;
			}
			if (! existsZimbraList(name)) {
				boolean singleUser = llista.getLlistaExterns().trim().isEmpty() && 
						llista.getLlistaLlistes().trim().isEmpty() &&
						users.equals(llista.getLlistaUsuaris()) &&
						!users.trim().contains(",");
				String owner = singleUser ? getUserEmail (users.trim()): null;
				
				String aliasOwner = getAliasOwner(name);
				if (singleUser)
				{
					if (owner != null &&  owner.equals(aliasOwner) )
					{
						// Nothing to do
						return;
					}
					
					if (aliasOwner != null)
					{
						// Remove existing alias
						// Create alias
						LinkedList<String> args = new LinkedList<String>();
						args.add(zimbraAdmin);
						args.add("-l");
						args.add("removeAccountAlias");
						args.add(aliasOwner);
						args.add(name);
						TimedProcess p = new TimedProcess(TIMEOUT);
						if (p.exec(args.toArray(new String[args.size()])) != 0) {
							throw new InternalErrorException("Error executing "
									+ concat(args) + ":\n" + p.getOutput()+p.getError());
						}
					}
					if (owner != null && ! owner.equals (name))
					{
						// Create alias
						LinkedList<String> args = new LinkedList<String>();
						args.add(zimbraAdmin);
						args.add("-l");
						args.add("addAccountAlias");
						args.add(owner);
						args.add(name);
						TimedProcess p = new TimedProcess(TIMEOUT);
						if (p.exec(args.toArray(new String[args.size()])) != 0) {
							throw new InternalErrorException("Error executing "
									+ concat(args) + ":\n" + p.getOutput()+p.getError());
						}
						if (createProfile)
						{
							Usuari u = getServer().getUserInfo(users.trim(), null);
							createAliasProfile(owner, name, u.getFullName());
						}
						return;
					}
					else
					{
						// Now create a normal list
					}
				}
				else if (aliasOwner != null)
				{
					// Remove existing alias
					// Create alias
					LinkedList<String> args = new LinkedList<String>();
					args.add(zimbraAdmin);
					args.add("-l");
					args.add("removeAccountAlias");
					args.add(aliasOwner);
					args.add(name);
					TimedProcess p = new TimedProcess(TIMEOUT);
					if (p.exec(args.toArray(new String[args.size()])) != 0) {
						throw new InternalErrorException("Error executing "
								+ concat(args) + ":\n" + p.getOutput()+p.getError());
					}
					// Now create a normal listt
				}
				LinkedList<String> args = new LinkedList<String>();
				args.add(zimbraAdmin);
				args.add("-l");
				args.add("createDistributionList");
				args.add(name);
				TimedProcess p = new TimedProcess(TIMEOUT);
				if (p.exec(args.toArray(new String[args.size()])) != 0) {
					throw new InternalErrorException("Error executing "
							+ concat(args) + ":\n" + p.getOutput()+p.getError());
				}

			}
			setListAliasMembers(name, llista, users);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error processing task", e);
		}
	}

	private void setListAliasMembers(String name, LlistaCorreu llista, String users)
			throws IOException, TimedOutException, InternalErrorException,
			es.caib.seycon.ng.exception.UnknownUserException {
		LinkedList<String> args = new LinkedList<String>();
		args.add(zimbraAdmin);
		args.add("-l");
		args.add("modifyDistributionList");
		args.add(name);
		args.add("displayName");
		args.add(llista.getDescripcio() == null ? name: llista.getDescripcio() );
		TimedProcess p = new TimedProcess(TIMEOUT);
		if (p.exec(args.toArray(new String[args.size()])) != 0) {
			throw new InternalErrorException("Error executing "
					+ concat(args) + ":\n" + p.getOutput()+p.getError());
		}
		Set<String> current = new HashSet<String>(getZimbraAliasMembers(name));
		Set<String> newMembers = new HashSet<String>();
		if (llista.getLlistaExterns().trim().length() > 0 )
			for (String extern : llista.getLlistaExterns().split("[ ,]+"))
				newMembers.add(extern.toLowerCase());

		if (llista.getLlistaLlistes().trim().length() > 0 )
			for (String extern : llista.getLlistaLlistes().split("[ ,]+"))
				newMembers.add(extern.toLowerCase());

		if (users.trim().length() > 0 )
			for (String user : users.split("[ ,]+")) {
				Usuari u = getServer().getUserInfo(user, null);
				if (u != null) {
					boolean found = false;
				
					for (Account acc : getServer().getUserAccounts(u.getId(),
							getCodi())) {
						newMembers.add(acc.getName().toLowerCase());
						found = true;
					}
					if (! found )
					{
						if (u.getDominiCorreu() != null)
							newMembers.add (u.getNomCurt()+"@"+u.getDominiCorreu().toLowerCase());
						else
						{
							DadaUsuari email = getServer().getUserData(u.getId(), "EMAIL");
							if (email != null && email.getValorDada() != null)
								newMembers.add (email.getValorDada().toLowerCase());
								
						}
					}
				}
			}

		// Adds new members
		for (String newMember : newMembers) {
			if (!current.contains(newMember)) {
				args = new LinkedList<String>();
				args.add(zimbraAdmin);
				args.add("-l");
				args.add("addDistributionListMember");
				args.add(name);
				args.add(newMember);
				p = new TimedProcess(TIMEOUT);
				if (p.exec(args.toArray(new String[args.size()])) != 0) {
					throw new InternalErrorException("Error executing "
							+ concat(args) + ":\n" + p.getOutput()+p.getError());
				}
			} else {
				current.remove(newMember);
			}
		}

		// Removes old members
		for (String oldMember : current) {
			args = new LinkedList<String>();
			args.add(zimbraAdmin);
			args.add("-l");
			args.add("removeDistributionListMember");
			args.add(name);
			args.add(oldMember);
			p = new TimedProcess(TIMEOUT);
			if (p.exec(args.toArray(new String[args.size()])) != 0) {
				throw new InternalErrorException("Error executing "
						+ concat(args) + ":\n" + p.getOutput()+p.getError());
			}
		}
	}

	public void removeListAlias(String nomLlista, String domini)
			throws InternalErrorException {
		try {
			if (!  mailDomains.contains( domini) )
				return;

			if (existsZimbraList(nomLlista + "@" + domini)) {
				LinkedList<String> args = new LinkedList<String>();
				args.add(zimbraAdmin);
				args.add("-l");
				args.add("deleteDistributionList");
				args.add(nomLlista + "@" + domini);
				TimedProcess p = new TimedProcess(TIMEOUT);
				if (p.exec(args.toArray(new String[args.size()])) != 0) {
					throw new InternalErrorException("Error executing "
							+ concat(args) + ":\n" + p.getOutput()+p.getError());
				}

			}
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error processing task", e);
		}
	}

	public List<RolGrant> getAccountGrants(String arg0) throws RemoteException,
			InternalErrorException {
		return new LinkedList<RolGrant>();
	}

	public Account getAccountInfo(String name) throws RemoteException,
			InternalErrorException {
		try {
			TimedProcess p = new TimedProcess(TIMEOUT);
			if (p.exec(new String[] { zimbraAdmin, "-l", "getAccount", name,
					"displayName" }) == 0) {
				Account acc = new Account();
				acc.setName(name);
				acc.setDispatcher(getCodi());
				final String prefix = "displayName: ";
				for (String s : p.getOutput().split("\n")) {
					if (s.startsWith(prefix))
						acc.setDescription(s.substring(prefix.length()));
				}
				return acc;
			} else {
				if (p.getError().indexOf("account.NO_SUCH_ACCOUNT") >= 0)
					return null;
				else
					throw new IOException("Error executing " + zimbraAdmin
							+ " -l getAccount " + name + " :\n" + p.getOutput()+p.getError());
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error processing task", e);
		}
	}
	
	private void createAliasProfile (String account, String alias, String description) throws InternalErrorException
	{
		try {
			TimedProcess p = new TimedProcess(TIMEOUT);
			if (p.exec(new String[] { zimbraMailbox, "-z", "-m", account, "cid", alias, "zimbraPrefFromAddress", alias,
					"zimbraPrefFromAddressType", "sendAs", "zimbraPrefFromDisplay", description,
					"zimbraPrefReplyToEnabled", "FALSE", "zimbraPrefWhenInFoldersEnabled", "FALSE",
					"zimbraPrefWhenSentToAddresses", alias, "zimbraPrefWhenSentToEnabled", "TRUE"}) != 0)
			{
				throw new IOException("Error executing " +  zimbraMailbox + " :\n" + p.getOutput()+p.getError());
			}
			if (p.exec(new String[] { zimbraAdmin, "mid", account, alias, "zimbraPrefIdentityName", description}) != 0)
			{
				throw new IOException("Error executing " + zimbraMailbox + " :\n" + p.getOutput()+p.getError());
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error processing task", e);
		}
	}
	
	public void configureMappings(Collection<ExtensibleObjectMapping> objects)
			throws RemoteException, InternalErrorException {
		objectMappings = objects;
		translator = new ObjectTranslator(getDispatcher(), getServer(), objectMappings);
	}

	private String getUsersList (LlistaCorreu llista)
	{
		try {
			Method m  = llista.getClass().getMethod("getExplodedUsersList");
			return (String) m.invoke(llista);
		} catch (NoSuchMethodException e ) {
			return llista.getLlistaUsuaris();
		} catch (IllegalAccessException e) {
			throw new RuntimeException (e);
		} catch (IllegalArgumentException e) {
			throw new RuntimeException (e);
		} catch (InvocationTargetException e) {
			throw new RuntimeException (e);
		}
			
	}
}
