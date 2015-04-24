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
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.comu.UserAccount;
import es.caib.seycon.ng.comu.Usuari;
//import es.caib.seycon.InternalErrorException;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.engine.extobj.AccountExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ObjectTranslator;
import es.caib.seycon.ng.sync.engine.extobj.UserExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
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

public class ZimbraAgent extends Agent implements UserMgr, MailAliasMgr,
		ReconcileMgr2 {
	/** zarfa-admin program */
	final static int TIMEOUT = 30000;
	private String zimbraAdmin;
	private String zimbraMailbox;
	boolean createProfile = false;
	private String fullNameExpression = null;

	/**
	 * Constructor
	 * 
	 * @param params
	 *            vector con parámetros de configuración: <LI>0 = usuario</LI>
	 *            <LI>1 = contraseña oracle</LI> <LI>2 = cadena de conexión a la
	 *            base de datos</LI> <LI>3 = contraseña con la que se protegerán
	 *            los roles</LI>
	 */
	public ZimbraAgent() throws java.rmi.RemoteException {
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
		fullNameExpression = getDispatcher().getParam3();
		log.info("Starting Zimbra Agent {}", getDispatcher().getCodi(), null);
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
		try {
			Account acc = new Account ();
			acc.setName(account);
			acc.setDescription(usu.getFullName());
			String fullName = getFullName(acc, usu);
			// Comprobar si el usuario existe
			if (existsZimbraUser(account)) {
				LinkedList<String> args = new LinkedList<String>();
				args.add(zimbraAdmin);
				args.add("-l");
				args.add("modifyAccount");
				args.add(account);
				args.add("zimbraAccountStatus");
				args.add("active");
				args.add("givenName");
				args.add(usu.getNom());
				args.add("sn");
				args.add(usu.getPrimerLlinatge()
						+ (usu.getSegonLlinatge() == null ? "" : " "
								+ usu.getSegonLlinatge()));
				args.add("displayName");
				args.add(fullName);
				TimedProcess p = new TimedProcess(TIMEOUT);
				if (p.exec(args.toArray(new String[args.size()])) != 0) {
					throw new InternalErrorException("Error executing "
							+ concat(args) + ":\n" + p.getOutput()+p.getError());
				}
			} else {
				Password pass = getServer().getOrGenerateUserPassword(account,
						getCodi());
				LinkedList<String> args = new LinkedList<String>();
				args.add(zimbraAdmin);
				args.add("-l");
				args.add("createAccount");
				args.add(account);
				args.add(pass.getPassword());
				args.add("givenName");
				args.add(usu.getNom());
				args.add("sn");
				args.add(usu.getPrimerLlinatge()
						+ (usu.getSegonLlinatge() == null ? "" : " "
								+ usu.getSegonLlinatge()));
				args.add("displayName");
				args.add(fullName);
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
				updateUser(account, usuari);
			}
			LinkedList<String> args = new LinkedList<String>();
			args.add(zimbraAdmin);
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
		} catch (RemoteException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (TimedOutException e) {
			throw new InternalErrorException("Error update password", e);
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
		try {
			// Comprobar si el usuario existe
			if (existsZimbraUser(account)) {
				LinkedList<String> args = new LinkedList<String>();
				args.add(zimbraAdmin);
				args.add("-l");
				args.add("modifyAccount");
				args.add(account);
				args.add("zimbraAccountStatus");
				args.add("closed");
//				args.add("deleteAccount");
				TimedProcess p = new TimedProcess(TIMEOUT);
				if (p.exec(args.toArray(new String[args.size()])) != 0) {
					throw new InternalErrorException("Error executing "
							+ concat(args) + ":\n" + p.getOutput()+p.getError());
				}
			}
		} catch (RemoteException e) {
			throw new InternalErrorException("Error disabling user", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error disabling user", e);
		} catch (TimedOutException e) {
			throw new InternalErrorException("Error disabling user", e);
		}
	}

	public void updateUser(String account, String descripcio)
			throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		try {
			Account acc = new Account ();
			acc.setName(account);
			acc.setDescription(descripcio);
			String fullName = getFullName(acc, null);
			// Comprobar si el usuario existe
			if (existsZimbraUser(account)) {
				LinkedList<String> args = new LinkedList<String>();
				args.add(zimbraAdmin);
				args.add("-l");
				args.add("modifyAccount");
				args.add(account);
				args.add("displayName");
				args.add(fullName);
				TimedProcess p = new TimedProcess(TIMEOUT);
				if (p.exec(args.toArray(new String[args.size()])) != 0) {
					throw new InternalErrorException("Error executing "
							+ concat(args) + ":\n" + p.getOutput()+p.getError());
				}
			} else {
				LinkedList<String> args = new LinkedList<String>();
				args.add(zimbraAdmin);
				args.add("createAccount");
				args.add(account);
				args.add("displayName");
				args.add(fullName);
				TimedProcess p = new TimedProcess(TIMEOUT);
				if (p.exec(args.toArray(new String[args.size()])) != 0) {
					throw new InternalErrorException("Error executing "
							+ concat(args) + ":\n" + p.getOutput()+p.getError());
				}

				Password pass = getServer().getOrGenerateUserPassword(account,
						getCodi());
				if (pass != null) {
					args = new LinkedList<String>();
					args.add(zimbraAdmin);
					args.add("-l");
					args.add("setPassword");
					args.add(account);
					args.add(pass.getPassword());
					p = new TimedProcess(TIMEOUT);
					if (p.exec(args.toArray(new String[args.size()])) != 0) {
						throw new InternalErrorException("Error executing "
								+ concat(args) + ":\n" + p.getOutput()+p.getError());
					}
				}
			}

		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error processing task", e);
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
			String name = llista.getNom() + "@" + llista.getCodiDomini();
			if (llista.getLlistaExterns() == null)
				llista.setLlistaExterns("");
			if (llista.getLlistaLlistes() == null)
				llista.setLlistaLlistes("");
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
			
			boolean singleUser = llista.getLlistaExterns().trim().isEmpty() && 
					llista.getLlistaLlistes().trim().isEmpty() &&
					users.equals(llista.getLlistaUsuaris()) &&
					!users.trim().contains(",");
			if (singleUser && existsZimbraList(name))
			{
				removeListAlias(llista.getNom(), llista.getCodiDomini());
			}
			
			if (! existsZimbraList(name)) {
				String owner = singleUser ? getUserEmail (users.trim()): null;
				
				String aliasOwner = getAliasOwner(name);
				if (aliasOwner == null && singleUser && owner != null && ! owner.equals (name))
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
						Usuari u = getServer().getUserInfo(users, null);
						createAliasProfile(owner, name, u.getFullName());
					}
					return;
				}
				else if (singleUser && owner != null && owner.equals(name))
				{
					// Nothing to do
					return;
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
			for (String user :  users.split("[ ,]+")) {
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
	
	private String getFullName (Account account, Usuari u) throws InternalErrorException
	{
		if (fullNameExpression == null || fullNameExpression.trim().length() == 0)
			return account.getDescription();
					
		ExtensibleObject eo = u == null ? new AccountExtensibleObject(account, getServer())
			: new UserExtensibleObject(account, u, getServer());
		ExtensibleObjectMapping eom = new ExtensibleObjectMapping();
		AttributeMapping am = new AttributeMapping();
		am.setSystemAttribute("fullName");
		am.setSoffidAttribute(fullNameExpression);
		am.setDirection(AttributeDirection.OUTPUT);
		am.setId((long) 0);
		am.setObjectId((long) 0);
		eom.setAttributes(new LinkedList<AttributeMapping>());
		eom.getAttributes().add(am);
		eom.setSoffidObject(SoffidObjectType.fromString(eo.getObjectType()));
		eom.setSystemObject(eo.getObjectType());

		ObjectTranslator ot = new ObjectTranslator(getDispatcher(), getServer(), 
				Collections.singleton(eom));
		String s =  (String) ot.generateAttribute("fullName", eo, eom);
		if ( s == null)
			throw new InternalErrorException("Error evaluating "+fullNameExpression+": null");
		if (! s.equals (account.getDescription()))
		{
			account.setDescription(s);
			if (u != null)
			{
				u.setFullName(s);
				int f = s.indexOf(' ');
				if ( f < 0)
				{
					u.setNom(s);
					u.setPrimerLlinatge("");
					u.setSegonLlinatge("");
				} else {
					u.setNom(s.substring(0, f));
					u.setPrimerLlinatge(s.substring(f+1));
					u.setSegonLlinatge("");
				}
			}
		}
		return s;
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
