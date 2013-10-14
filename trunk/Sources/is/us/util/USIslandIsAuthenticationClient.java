package is.us.util;

import java.io.*;
import java.security.PublicKey;
import java.security.cert.*;
import java.util.*;

import javax.net.ssl.*;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.*;

import org.slf4j.*;
import org.w3c.dom.*;
import org.xml.sax.SAXException;

/**
 * Handle communications with the island.is authentication service. See
 * http://en.wikipedia.org/wiki/Security_Assertion_Markup_Language for
 * information about SAML
 */
public class USIslandIsAuthenticationClient {

	private static final Logger				logger				= LoggerFactory.getLogger( USIslandIsAuthenticationClient.class );

	private static final String				IP_KEY				= "IP";
	private static final String				TOKEN_KEY			= "TOKEN";
	private static final String				SSN_KEY				= "SSN";
	private static final String				SYSID_KEY			= "SYSID";
	private static final String				AUTHMETHOD_KEY		= "AUTHMETHOD";																	// TODO: implement me
	private static final String				STATUS_CODE_KEY		= "status.code";

	private static final String				CRLF				= "\r\n";
	private static final String				USER_AGENT_NAME		= "is.us.island.authenticate";
	private static final String				CONTENT_TYPE		= "text/xml";

	private static final String				SAML_SERVER			= "egov.webservice.is";
	private static final String				SAML_PATH			= "/sst/runtime.asvc/com.actional.soapstation.eGOVDKM_AuthConsumer.AccessPoint";
	private static final String				SOAP_METHOD			= "generateSAMLFromToken";
	private static final int				SAML_SERVER_PORT	= 443;
	private static final int				SOCKET_TIMEOUT_MS	= 4000;

	private String							_token;
	private String							_userIp;
	private String							_username;
	private String							_password;
	private String							_samlResponse;

	private Map<String, String>				_samlInfo;
	private static DocumentBuilderFactory	dbf					= DocumentBuilderFactory.newInstance();
	static {
		dbf.setNamespaceAware( true );
	}

	/**
	 * Never construct this class using the default constructor, certain
	 * parameters required.
	 */
	@SuppressWarnings( "unused" )
	private USIslandIsAuthenticationClient( ) {}

	/**
	 * @param token the login token received from island.is
	 * @param userIp the users IP address
	 * @param username the island.is authentication service username
	 * @param password the island.is authentication service password
	 * @param keystorePath the path to the key store file
	 * @param keystorePassword the password for the key store
	 */
	public USIslandIsAuthenticationClient( String token, String userIp, String username, String password, String keystorePath, String keystorePassword ) {
		_token = token;
		_userIp = userIp;
		_username = username;
		_password = password;

		logger.debug( "Using keystore file at: " + keystorePath );
		System.setProperty( "javax.net.ssl.trustStore", keystorePath );
		System.setProperty( "javax.net.ssl.trustStorePassword", keystorePassword );
	}

	public void authenticate() throws USIslandIsAuthenticationException {
		parseSaml();// initiate the soap communications
	}

	/**
	 * @return The Token currently being used.
	 */
	public String token() {
		return _token;
	}

	/**
	 * @return The sysid (identifier of the system that handled the login) from
	 *         the SAML response.
	 */
	public String sysid() {
		Map<String, String> samlInfo = samlInfo();

		if ( samlHasErrorStatus( samlInfo ) || !samlInfo.containsKey( SYSID_KEY ) ) {
			return null;
		}

		return samlInfo.get( SYSID_KEY );
	}

	/**
	 * @param samlInfo
	 * @return
	 */
	private boolean samlHasErrorStatus( Map<String, String> samlInfo ) {
		return (samlInfo.containsKey( STATUS_CODE_KEY ) && !samlInfo.get( STATUS_CODE_KEY ).equals( "0" ));
	}

	private Map<String, String> samlInfo() {
		if ( _samlInfo == null ) {
			_samlInfo = parseSaml();
		}
		return _samlInfo;
	}

	/**
	 * @return The user persidno from the saml response
	 * @throws USIslandIsAuthenticationException if there is an error getting
	 *         the persidno
	 */
	public String persidno() {
		Map<String, String> samlInfo = samlInfo();

		if ( (samlInfo == null) || !samlInfo.containsKey( SSN_KEY ) || samlHasErrorStatus( samlInfo ) ) {
			String errorMessage;

			if ( samlInfo == null ) {
				errorMessage = "samlInfo == null";
			}
			else {
				errorMessage = "SSN = " + samlInfo.get( SSN_KEY ) + " status.code = " + samlInfo.get( STATUS_CODE_KEY );
			}
			throwIslandIsAuthenticationException( errorMessage );
		}

		return samlInfo.get( SSN_KEY );
	}

	public String samlResponse() {
		return _samlResponse;
	}

	/**
	 * Parses the SAML message, from the soap response, and extracts the status
	 * code/message and user ssn.
	 * 
	 * @return the information from the SAML message
	 * @throws USIslandIsAuthenticationException if there is an error getting
	 *         the SAML info
	 */
	private Map<String, String> parseSaml() {
		Map<String, String> info = new HashMap<String, String>();
		info.put( TOKEN_KEY, _token );
		info.put( IP_KEY, _userIp );

		Document docXML = null;

		_samlResponse = sendSoapRequest();

		docXML = parseXml( _samlResponse );

		checkSoapForFaults( info, docXML );

		// fetch the soap function response from the soap body
		Node soapResponseCertSaml = getFirstNodeByTagName( docXML, "generateSAMLFromTokenResponse" );

		// Check for SAML error
		checkSamlForErrors( info, soapResponseCertSaml );

		// fetch the saml message from the soap function response
		Node saml = getFirstNodeByTagName( docXML, "saml" );
		String samlContent = saml.getFirstChild().getNodeValue().trim();

		Node assertionEl = null;
		// if the saml assertion is html encoded we need to re-parse it
		if ( samlContent.startsWith( "<" ) ) {
			docXML = parseXml( samlContent );
		}
		assertionEl = getFirstNodeByTagName( docXML, "Assertion", "urn:oasis:names:tc:SAML:1.0:assertion" );
		insertAttributesInMap( info, assertionEl );
		try {
			System.out.println( "validateSamlAssertion:" + validateSamlAssertion( docXML ) );
		}
		catch ( Exception e ) {
			e.printStackTrace();
		}

		_samlInfo = info;
		for ( String key : info.keySet() ) {
			System.out.println( key + " = " + info.get( key ) );
		}
		return _samlInfo;
	}

	/**
	 * wrapper, that handles the exceptions, for {@link javax.xml.parsers.DocumentBuilder#parse(InputStream ) }
	 * @param xml string
	 * @return {@link org.w3c.dom.Document} 
	 */
	public Document parseXml( String xml ) {
		try {
			return dbf.newDocumentBuilder().parse( new ByteArrayInputStream( xml.getBytes( "UTF-8" ) ) );
		}
		catch ( SAXException e ) {
			throwIslandIsAuthenticationException( "Error parsing xml message", e );
		}
		catch ( ParserConfigurationException e ) {
			throwIslandIsAuthenticationException( "Error parsing saml", e );
		}
		catch ( IOException e ) {
			throwIslandIsAuthenticationException( "Error parsing soap message", e );
		}
		return null;// we will never reach this part
	}

	/**
	 * Returns the first element in the list returned from {@link org.w3c.dom.Document#getElementsByTagNameNS(String, String) }
	 */
	private Node getFirstNodeByTagName( Document doc, String tagName ) {
		return getFirstNodeByTagName( doc, tagName, null );
	}

	/**
	 * Returns the first element in the list returned from {@link org.w3c.dom.Document#getElementsByTagNameNS(String, String) }
	 */
	private Node getFirstNodeByTagName( Document doc, String tagName, String namespace ) {
		NodeList list;
		if ( namespace != null ) {
			list = doc.getElementsByTagNameNS( namespace, tagName );
		}
		else {
			list = doc.getElementsByTagName( tagName );
		}
		if ( (list != null) && (list.getLength() > 0) ) {
			return list.item( 0 );
		}
		return null;
	}

	/**
	 * Gets the attributes from the assertion and puts them in a map
	 * 
	 * @param info the map to put the attributes in
	 * @param assertion the assertion
	 */
	private void insertAttributesInMap( Map<String, String> info, Node assertion ) {
		Node attributeStatement = ((Element)assertion).getElementsByTagName( "AttributeStatement" ).item( 0 );//firstChild( assertion, "AttributeStatement", "urn:oasis:names:tc:SAML:1.0:assertion" );
		NodeList attributesNodes = attributeStatement.getChildNodes();
		// Insert all the attributes, from the Attributestatement tag, into the info dictionary
		for ( int i = 0; i < attributesNodes.getLength(); i++ ) {
			Node child = attributesNodes.item( i );

			if ( child.getLocalName().equals( "Attribute" ) ) {
				String key = null;
				String val;
				NamedNodeMap attributes = child.getAttributes();
				for ( int a = 0; a < attributes.getLength(); a++ ) {
					Node att = attributes.item( a );
					if ( att.getLocalName().equals( "AttributeName" ) ) {
						key = att.getTextContent();
						break;
					}
				}
				val = child.getChildNodes().item( 0 ).getTextContent();
				if ( key != null ) {
					info.put( key, val );
				}
			}
		}
	}

	/**
	 * Handles the SAML request/response through a SSL socket
	 * @return the response from the island.is authentication service
	 */
	private String sendSoapRequest() {

		SSLSocketFactory sf = (SSLSocketFactory)SSLSocketFactory.getDefault();
		SSLSocket socket = null;
		StringBuilder response = new StringBuilder();

		try {
			socket = (SSLSocket)sf.createSocket( SAML_SERVER, SAML_SERVER_PORT );
			socket.setSoTimeout( SOCKET_TIMEOUT_MS );

			socket.startHandshake();
			PrintWriter dataOut = new PrintWriter( socket.getOutputStream() );
			BufferedReader dataIn = new BufferedReader( new InputStreamReader( socket.getInputStream() ) );
			dataOut.write( soapMessageHeaders( _token, _userIp, _username, _password ) );
			dataOut.write( soapMessageBody( _token, _userIp ) );
			dataOut.flush();

			StringBuilder xmlResponseHeaders = new StringBuilder();

			// Read the response headers
			String line;

			while ( (line = dataIn.readLine()) != null ) {
				if ( line.length() == 0 ) {
					break;
				}
				xmlResponseHeaders.append( line + CRLF );
			}

			logger.debug( "island.is xml response headers: " + xmlResponseHeaders.toString() );

			// Read the response body
			while ( (line = dataIn.readLine()) != null ) {
				response.append( line + CRLF );
			}
		}
		catch ( NoClassDefFoundError e ) {
			throwIslandIsAuthenticationException( "SSLSocket handshake error", e );
		}
		catch ( IOException e ) {
			throwIslandIsAuthenticationException( "IOException when communicating with island.is", e );
		}
		finally {
			try {
				socket.close();
			}
			catch ( Exception e ) {
				logger.error( "Failed to close island.is communications socket", e );
			}
		}

		return response.toString();
	}

	/**
	 * @param token the login token received from island.is
	 * @param userIp the users IP address
	 * @param username the island.is authentication service username
	 * @param password the island.is authentication service password
	 * @return The SOAP request headers
	 */
	private String soapMessageHeaders( String token, String userIp, String username, String password ) {
		StringBuilder headers = new StringBuilder();

		headers.append( "POST " + SAML_PATH + " HTTP/1.0" + CRLF );
		headers.append( "User-Agent: " + USER_AGENT_NAME + CRLF );
		headers.append( "Host: us.is" + CRLF );
		headers.append( "Content-Type: " + CONTENT_TYPE + CRLF );
		headers.append( "Authorization: " + "Basic " + DatatypeConverter.printBase64Binary( new String( username + ":" + password ).getBytes() ) + CRLF );
		headers.append( "Content-Length: " + soapMessageBody( token, userIp ).length() + CRLF );
		headers.append( "Soapaction: " + SOAP_METHOD + CRLF );
		headers.append( CRLF );

		return headers.toString();
	}

	/**
	 * @param token the login token received from island.is
	 * @param userIp the users IP address
	 * @return The soap request body.
	 */
	private String soapMessageBody( String token, String userIp ) {
		StringBuilder body = new StringBuilder();

		body.append( "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>" + CRLF );
		body.append( "<soapenv:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"" + CRLF );
		body.append( " xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"" + CRLF );
		body.append( " xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"" + CRLF );
		body.append( " xmlns:egov=\"http://www.kogun.is/eGov/eGovSAMLGenerator.webServices\">" + CRLF );
		body.append( "<soapenv:Header/>" + CRLF );
		body.append( "<soapenv:Body>" + CRLF );
		body.append( "<egov:generateSAMLFromToken soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" + CRLF );
		body.append( "<token xsi:type=\"xsd:string\">" + token + "</token>" + CRLF );
		body.append( "<ipAddress xsi:type=\"xsd:string\">" + userIp + "</ipAddress>" + CRLF );
		body.append( "</egov:generateSAMLFromToken>" + CRLF );
		body.append( "</soapenv:Body>" + CRLF );
		body.append( "</soapenv:Envelope>" + CRLF );

		return body.toString();
	}

	/**
	 * Validates the xml signature
	 * @param samlDoc 
	 * @return
	 */
	public boolean validateSamlAssertion( Document samlDoc ) {

		// Find Signature element
		NodeList nl = samlDoc.getElementsByTagNameNS( XMLSignature.XMLNS, "Signature" );
		if ( nl.getLength() == 0 ) {
			throwIslandIsAuthenticationException( "Can't find assertion Signature element" );
		}

		XMLSignatureFactory fac = XMLSignatureFactory.getInstance( "DOM" );

		NodeList rsa = samlDoc.getElementsByTagNameNS( XMLSignature.XMLNS, "X509Certificate" );
		PublicKey publicKey = null;
		try {
			publicKey = loadCertificate( rsa.item( 0 ).getTextContent() );
		}
		catch ( CertificateException e ) {
			throwIslandIsAuthenticationException( "Assertion certificate is not valid", e );
		}
		catch ( DOMException e ) {
			throwIslandIsAuthenticationException( "Can't find the Assertion certificate", e );
		}

		DOMValidateContext valContext = new DOMValidateContext( publicKey, nl.item( 0 ) );

		// no schema used so we need to explicitly register id attribute
		NodeList foo = samlDoc.getElementsByTagNameNS( "urn:oasis:names:tc:SAML:1.0:assertion", "Assertion" );
		valContext.setIdAttributeNS( (Element)foo.item( 0 ), null, "AssertionID" );
		((Element)foo.item( 0 )).setIdAttribute( "AssertionID", true );

		// unmarshal the XMLSignature
		XMLSignature signature = null;
		try {
			signature = fac.unmarshalXMLSignature( valContext );
		}
		catch ( MarshalException e ) {
			throwIslandIsAuthenticationException( "Error unmarshaling the Assertion signature", e );
		}

		// Validate the XMLSignature (generated above)
		try {
			signature.validate( valContext );
		}
		catch ( XMLSignatureException e ) {
			throwIslandIsAuthenticationException( "The assertion signature is not valid!", e );
		}
		return true;
	}

	/**
	 * Loads the certificate from base64 encoded string and returns it's public key
	 * @param certificate base64 encoded string
	 * @throws CertificateException if the certificate is invalid or not found
	 */
	private PublicKey loadCertificate( String certificate ) throws CertificateException {
		CertificateFactory fty = CertificateFactory.getInstance( "X.509" );
		ByteArrayInputStream bais = new ByteArrayInputStream( DatatypeConverter.parseBase64Binary( certificate ) );
		return fty.generateCertificate( bais ).getPublicKey();
	}

	/**
	 * Check for faults in the SOAP messages and sets them in the information
	 * dictionary
	 * 
	 * @param info the dictionary to set the fault messages in
	 * @param body the {@link nu.xom.Element} (SOAP message) to check for faults
	 */
	private void checkSoapForFaults( Map<String, String> info, Document doc ) {
		Node fault = getFirstNodeByTagName( doc, "Fault" );
		if ( fault != null ) {
			NodeList faultAttributes = fault.getChildNodes();
			for ( int i = 0; i < faultAttributes.getLength(); i++ ) {
				Node child = faultAttributes.item( i );
				String key = child.getLocalName();
				String val = child.getTextContent();
				info.put( key, val );
				logger.error( key + " = " + val );
			}
			throwIslandIsAuthenticationException( "SOAP message is not valid!" );
		}
	}

	/**
	 * Checks for error status codes in the SAML and sets them in the
	 * information dictionary
	 * 
	 * @param info the dictionary to set the error messages in
	 * @param soapResponseCertSaml the SAML to get status codes from
	 * @throws USIslandIsAuthenticationException if the are errors
	 */
	private void checkSamlForErrors( Map<String, String> info, Node statusNode ) {
		if ( statusNode == null ) {
			return;
		}
		Element status = (Element)statusNode;
		String type = status.getElementsByTagName( "type" ).item( 0 ).getTextContent();
		String code = status.getElementsByTagName( "code" ).item( 0 ).getTextContent();
		String msg = status.getElementsByTagName( "message" ).item( 0 ).getTextContent();
		info.put( "status.type", type );
		info.put( "status.code", code );
		info.put( "status.message", msg );
		if ( !code.equals( "0" ) ) {
			throwIslandIsAuthenticationException( "SAML message is not valid! Error type=" + type + ", code=" + code + ", msg=" + msg );
		}
	}

	private void throwIslandIsAuthenticationException( String msg, Throwable e ) {
		logger.error( msg );
		throw new USIslandIsAuthenticationException( msg, e );
	}

	private void throwIslandIsAuthenticationException( String msg ) {
		logger.error( msg );
		throw new USIslandIsAuthenticationException( msg );

	}

}
