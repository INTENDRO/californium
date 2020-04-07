/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.net.InetSocketAddress;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.InMemoryPskStore;
import org.eclipse.californium.scandium.dtls.CertificateType;


public class SecureServer_seTraining {

	// allows configuration via Californium.properties
	public static final int DTLS_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_SECURE_PORT);

	private static final String TRUST_STORE_PASSWORD = "teamwireless";//"rootPass";
	private final static String KEY_STORE_PASSWORD = "teamwireless";//"endPass";
	private static final String KEY_STORE_LOCATION = "alpha_server_keystore.jks"; //"certs/keyStore.jks";
	private static final String TRUST_STORE_LOCATION = "alpha_server_keystore.jks"; //"certs/trustStore.jks";
	private static final String SERVER_ADDR = "2a02:168:41ff:0:fc52:8be9:a42c:d07f";
	
	// private static final String TOGGLE_PATH[] = {"/bin/sh", "/home/sepi/scripts/toggle_led.sh"};
	
	public static void main(String[] args) {

		InetSocketAddress read_addr;
		
		CoapServer server = new CoapServer();
		
		server.add(new CoapResource("secure") {
			@Override
			public void handleGET(CoapExchange exchange) {
				exchange.respond(ResponseCode.CONTENT, "hello security");
				
				// try {
				// 	@SuppressWarnings("unused")
				// 	Process pr = Runtime.getRuntime().exec(TOGGLE_PATH);
				// } catch (IOException e) {
				// 	// TODO Auto-generated catch block
				// 	e.printStackTrace();
				// }
			}
		});
		
		// ETSI Plugtest environment
		// server.addEndpoint(new CoAPEndpoint(new DTLSConnector(new InetSocketAddress("::1", DTLS_PORT)), NetworkConfig.getStandard()));
		// server.addEndpoint(new CoAPEndpoint(new DTLSConnector(new InetSocketAddress("127.0.0.1", DTLS_PORT)), NetworkConfig.getStandard()));
		// server.addEndpoint(new CoAPEndpoint(new DTLSConnector(new InetSocketAddress("2a01:c911:0:2010::10", DTLS_PORT)), NetworkConfig.getStandard()));
		// server.addEndpoint(new CoAPEndpoint(new DTLSConnector(new InetSocketAddress("10.200.1.2", DTLS_PORT)), NetworkConfig.getStandard()));

		try {
			// Pre-shared secrets
			InMemoryPskStore pskStore = new InMemoryPskStore();
			pskStore.setKey("Client_identity", "secretPSK".getBytes()); // from ETSI Plugtest test spec

			// load the trust store
			KeyStore trustStore = KeyStore.getInstance("JKS");
			InputStream inTrust = SecureServer_seTraining.class.getClassLoader().getResourceAsStream(TRUST_STORE_LOCATION);
			trustStore.load(inTrust, TRUST_STORE_PASSWORD.toCharArray());

			// You can load multiple certificates if needed
			// Certificate[] trustedCertificates = new Certificate[2];
			// trustedCertificates[0] = trustStore.getCertificate("ines_ca"); //"root"
			// trustedCertificates[1] = trustStore.getCertificate("ca_chain"); //"chain of the InES root and the Infineon root"

			Certificate[] trustedCertificates = new Certificate[1];
			trustedCertificates[0] = trustStore.getCertificate("nosd_ca"); //"root"

			System.out.println(trustedCertificates[0].toString());

			// load the key store
			KeyStore keyStore = KeyStore.getInstance("JKS");
			InputStream in = SecureServer_seTraining.class.getClassLoader().getResourceAsStream(KEY_STORE_LOCATION);
			keyStore.load(in, KEY_STORE_PASSWORD.toCharArray()); // KEY_STORE_PASSWORD

			DtlsConnectorConfig.Builder config = new DtlsConnectorConfig.Builder(); 
			config.setServerOnly(true);
			config.setAddress(new InetSocketAddress(SERVER_ADDR, DTLS_PORT));
			config.setSupportedCipherSuites(new CipherSuite[]{CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
			config.setPskStore(pskStore);
			config.setIdentity((PrivateKey)keyStore.getKey("nosd_server", KEY_STORE_PASSWORD.toCharArray()),
					keyStore.getCertificateChain("nosd_server"), (List<CertificateType>)null); 
			config.setTrustStore(trustedCertificates);
			
			config.setRetransmissionTimeout(10000);
			config.setMaxRetransmissions(3);
			config.setClientAuthenticationRequired(true);

			DTLSConnector connector = new DTLSConnector(config.build());

			read_addr = connector.getAddress();
			System.out.println(read_addr.toString());

			// use CoapEndpoint.Builder to create an endpoint with connector and standard network configuration
			CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
			builder.setConnector(connector);
			server.addEndpoint(builder.build()); 
			server.start();

		} catch (GeneralSecurityException | IOException e) {
			System.err.println("Could not load the keystore");
			e.printStackTrace();
		}

		// add special interceptor for message traces
		for (Endpoint ep : server.getEndpoints()) {
			ep.addInterceptor(new MessageTracer());
		}

		System.out.println("Secure CoAP server powered by Scandium (Sc) is listening on port " + DTLS_PORT);
	}

}
