package com.redhat.qe.xmlrpc;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthPolicy;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.contrib.auth.NegotiateScheme;
import org.apache.commons.httpclient.params.DefaultHttpParams;
import org.apache.commons.httpclient.params.HttpConnectionManagerParams;
import org.apache.commons.httpclient.params.HttpParams;
import org.apache.ws.commons.util.NamespaceContextImpl;
import org.apache.xmlrpc.XmlRpcException;
import org.apache.xmlrpc.client.XmlRpcClient;
import org.apache.xmlrpc.client.XmlRpcClientConfigImpl;
import org.apache.xmlrpc.client.XmlRpcCommonsTransportFactory;
import org.apache.xmlrpc.common.TypeFactoryImpl;
import org.apache.xmlrpc.common.XmlRpcController;
import org.apache.xmlrpc.common.XmlRpcStreamConfig;
import org.apache.xmlrpc.parser.NullParser;
import org.apache.xmlrpc.parser.TypeParser;
import org.apache.xmlrpc.serializer.NullSerializer;

import com.redhat.qe.tools.SSLCertificateTruster;

public class Session {

	protected String userName;
	protected String password;
	protected URL url;
	protected static XmlRpcClient client = null;
	protected Integer userid;

	public Session(String userName, String password, URL url) {
		this.userName = userName;
		this.password = password;
		this.url = url;
	}

	public synchronized void init() throws XmlRpcException, GeneralSecurityException, IOException {
		if (client == null) {
			SSLCertificateTruster.trustAllCertsForApacheXMLRPC();
		
			// setup client
			XmlRpcClientConfigImpl config = new XmlRpcClientConfigImpl();
			config.setServerURL(url);
		
			client = new XmlRpcClient();
			client.setConfig(config);
			XmlRpcCommonsTransportFactory factory = new XmlRpcCommonsTransportFactory(client);
		    HttpClient httpclient = new HttpClient();
		    MultiThreadedHttpConnectionManager cm = new MultiThreadedHttpConnectionManager();
		    HttpConnectionManagerParams connparams = new HttpConnectionManagerParams();
		    connparams.setConnectionTimeout(15000);
		    connparams.setDefaultMaxConnectionsPerHost(32);
		    connparams.setMaxTotalConnections(32);
		    cm.setParams(connparams);
		    httpclient.setHttpConnectionManager(cm);
		    factory.setHttpClient(httpclient);
		    client.setTypeFactory(new MyTypeFactory(client));
		    client.setTransportFactory(factory);
		    client.setMaxThreads(32);
	        List<String> schemes = new ArrayList<String>();
	        String jaas_user = "not_needed_for_kerb";
	        String jaas_pw = "not_needed_for_kerb";
	        	
		    if (userName != null && password != null) {
		    	factory.getHttpClient().getState().setCredentials(
		    		new AuthScope(url.getHost(), 443, AuthScope.ANY_REALM), new UsernamePasswordCredentials(userName, password));
		        schemes.add(AuthPolicy.BASIC);
		        jaas_user = userName;
		        jaas_pw = password;
		        
		    }
		    // register the auth scheme
	        AuthPolicy.registerAuthScheme("Negotiate", NegotiateScheme.class);
	
	        // include the scheme in the AuthPolicy.AUTH_SCHEME_PRIORITY preference
	        schemes.add("Negotiate");
	
	        HttpParams params = DefaultHttpParams.getDefaultParams();        
	        params.setParameter(AuthPolicy.AUTH_SCHEME_PRIORITY, schemes);
	        
	        Credentials use_jaas_creds = new UsernamePasswordCredentials(jaas_user, jaas_pw);
	        factory.getHttpClient().getState().setCredentials(
	            new AuthScope(null, -1, AuthScope.ANY_REALM),
	            use_jaas_creds);
		}

	}

	public XmlRpcClient getClient() {
		return client;
	}

	public Object login() throws XmlRpcException, GeneralSecurityException,
	IOException {
		return login("Auth.login", "login", userName, "password", password,
		"id");
	}

	public Object login(String loginMethod, String loginKey, String login,
		String passKey, String password, String returnKey)
		throws XmlRpcException, GeneralSecurityException, IOException {
	init();
	HashMap<String, Object> map = new HashMap<String, Object>();
	map.put(loginKey, login);
	map.put(passKey, password);
	ArrayList<Object> params = new ArrayList<Object>();
	params.add(map);
	
	HashMap<String, Object> hash = (HashMap<String, Object>) client
			.execute(loginMethod, params);
	this.userid = (Integer) hash.get(returnKey);
	return hash;
	
	}
	
	/**
	* @return the userid
	*/
	public Integer getUserid() {
	return userid;
	}

	public void setUserid(Integer userid) {
	this.userid = userid;
	}
				
	public class MyTypeFactory extends TypeFactoryImpl {

		public MyTypeFactory(XmlRpcController pController) {
			super(pController);
		}

		@Override
		public TypeParser getParser(XmlRpcStreamConfig pConfig,
				NamespaceContextImpl pContext, String pURI, String pLocalName) {

			if ("".equals(pURI) && NullSerializer.NIL_TAG.equals(pLocalName)) {
				return new NullParser();
			} else {
				return super.getParser(pConfig, pContext, pURI, pLocalName);
			}
		}
	}

}

