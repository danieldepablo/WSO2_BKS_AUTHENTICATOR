package com.santander.serenity.security.credentials.bkstoken;

import org.apache.axiom.util.base64.Base64Utils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.StringReader;
import java.util.*;

public class BKSToken {

    private static final String ISO_CHAR_SET = "ISO-8859-1";
    private static final String DELIMITER = "#";
    private static final int TOKEN_PARAMS_LENGTH = 10;
    private static final String USER_ID = "userID";
    private static final String LOCAL_EMITTER = "localEmitter";
    private static final String USER_CORP = "userCorp";
    private String originalData;
    private String securityId;
    private String userAddress;
    private long expirationDate;
    private Map<String, Object> userData;
    private String userId;
    private String userCorp;
    private String localEmitter;
    private String xmlData;
    private String cipherMethod;
    private String version;
    private String emitter;
    private String encryptedXmlData;
    private String signatureMethod;
    private String signature;

    /**
     * Parse a BKS token.
     *
     * @param token String bks token.
     * @return BKSToken Object BKSToken with token info.
     * @throws RuntimeException If token format is not correct.
     */
    public static BKSToken parse(final String token) {



        BKSToken bksToken = null;

        try {



            String credentialValue = new String(Base64Utils.decode(token), ISO_CHAR_SET);

            // Creamos el CredentialInfoBean para rellenar con los datos parseados y un tokenizer para desmontar el token
            bksToken = new BKSToken();
            String[] valueST = credentialValue.split(DELIMITER);

            if (valueST.length != TOKEN_PARAMS_LENGTH) {
                throw new RuntimeException("Wrong number of parameters. Expected=" + TOKEN_PARAMS_LENGTH + ". Found=" + valueST.length);
            }

            bksToken.setOriginalData(credentialValue);
            int i = 0;
            // SecurityID
            bksToken.setSecurityId(valueST[i++]);

            // IP, Direccion de usuario
            bksToken.setUserAddress(valueST[i++]);

            // FC, Fecha de caducidad
            bksToken.setExpirationDate(Long.parseLong(valueST[i++]));

            // XML de datos de usuario en B64
            String userDataXMLB64 = valueST[i++];

            // XML de datos de usuario en claro, siempre codificados en ISO-8859-1
            String userDataXML = new String(Base64Utils.decode(userDataXMLB64), ISO_CHAR_SET);

            // Mapa con los datos de usuario
            Map<String, Object> userDataMap = getDataFromXML(userDataXML);
            bksToken.setUserData(userDataMap);

            bksToken.setUserId((String) userDataMap.get(USER_ID));
            bksToken.setUserCorp((String) userDataMap.get(USER_CORP));
            bksToken.setLocalEmitter((String) userDataMap.get(LOCAL_EMITTER));

            // Establecemos el XML
            bksToken.setXmlData(userDataXML);

            // TC, DESede/CBC/PKCS5Padding
            bksToken.setCipherMethod(valueST[i++]);

            // VT, Version del token
            bksToken.setVersion(valueST[i++]);

            // ET, Emisor del token
            bksToken.setEmitter(valueST[i++]);

            // XML_CIFRADO, Cadena de datos de usuario cifrada
            String cipherXmlUserData = valueST[i++];
            bksToken.setEncryptedXmlData(cipherXmlUserData);

            // TF, Metodo de firma
            bksToken.setSignatureMethod(valueST[i++]);

            // Firma
            bksToken.setSignature(valueST[i++]);
        } catch (IllegalArgumentException | ParserConfigurationException | IOException | SAXException e) {
            throw new RuntimeException("Error parsing token", e);
        }


        return bksToken;
    }

    /**
     * Extract user data from user data XML.
     *
     * @param xmlData    User XML data.
     * @return A map indexed by node name containing the user data values.
     */
    private static Map<String, Object> getDataFromXML(String xmlData) throws ParserConfigurationException, IOException, SAXException {
//		logger.debug("Entering getDataFromXML(xmlData={})", xmlData);

        DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));

        Element root = doc.getDocumentElement();
        NodeList nodeList = doc.getDocumentElement().getChildNodes();
        int nodeListLength = nodeList.getLength();
        Set<String> hsNodeNames = new HashSet<>();
        for (int i = 0; i < nodeListLength; i++) {
            String nodeName = nodeList.item(i).getNodeName();
            hsNodeNames.add(nodeName);
        }

        Map<String, Object> resultData = new HashMap<>();
        for (String nodeName : hsNodeNames) {
            NodeList nodes = root.getElementsByTagName(nodeName);
            int longNode = root.getElementsByTagName(nodeName).getLength();

            if (longNode > 1) {
                List<String> alValue = new ArrayList<>(longNode);
                for (int j = 0; j < longNode; j++) {
                    String value = nodes.item(j).getFirstChild().getNodeValue();
                    alValue.add(value);
                }
                resultData.put(nodeName, alValue);
            } else {
                if (nodes.item(0) != null) {
                    String value = nodes.item(0).getFirstChild().getNodeValue();
                    resultData.put(nodeName, value);
                }
            }
        }

//		logger.debug("Leaving getDataFromXML()");
        return resultData;
    }

    /**
     * Gets cipher method.
     *
     * @return String the cipher method.
     */
    public String getCipherMethod() {
        return cipherMethod;
    }

    /**
     * Set cipher method.
     *
     * @param cipherMethod The cipher method.
     */
    public void setCipherMethod(String cipherMethod) {
        this.cipherMethod = cipherMethod;
    }

    /**
     * Gets emitter.
     *
     * @return String the emitter.
     */
    public String getEmitter() {
        return emitter;
    }

    /**
     * Set emitter.
     *
     * @param emitter The emitter.
     */
    public void setEmitter(String emitter) {
        this.emitter = emitter;
    }

    /**
     * Gets XML encrypted data.
     *
     * @return String the XML encrypted data token.
     */
    public String getEncryptedXmlData() {
        return encryptedXmlData;
    }

    /**
     * Set XML encrypted data.
     *
     * @param encryptedXmlData The XML encrypted data.
     */
    public void setEncryptedXmlData(String encryptedXmlData) {
        this.encryptedXmlData = encryptedXmlData;
    }

    /**
     * Gets expiration token date.
     *
     * @return String the expiration token date.
     */
    public long getExpirationDate() {
        return expirationDate;
    }

    /**
     * Set expiration token date.
     *
     * @param expirationDate The expiration token date.
     */
    public void setExpirationDate(long expirationDate) {
        this.expirationDate = expirationDate;
    }

    /**
     * Gets local emmitter.
     *
     * @return String the local emitter.
     */
    public String getLocalEmitter() {
        return localEmitter;
    }

    /**
     * Set local emitter.
     *
     * @param localEmitter The local emitter.
     */
    public void setLocalEmitter(String localEmitter) {
        this.localEmitter = localEmitter;
    }

    /**
     * Gets original token.
     *
     * @return String the original token.
     */
    public String getOriginalData() {
        return originalData;
    }

    /**
     * Set original token.
     *
     * @param originalData The original token.
     */
    public void setOriginalData(String originalData) {
        this.originalData = originalData;
    }

    /**
     * Gets original token without signature (ideal to verify sign)..
     *
     * @return String the original token without signature.
     */
    public String getOriginalDataWithoutSignature() {
        int lastIndex = getOriginalData().lastIndexOf(DELIMITER);
        return getOriginalData().substring(0, lastIndex + 1);
    }

    /**
     * Gets security Id.
     *
     * @return String Security Id.
     */
    public String getSecurityId() {
        return securityId;
    }

    /**
     * Set security id.
     *
     * @param securityId The original token.
     */
    public void setSecurityId(String securityId) {
        this.securityId = securityId;
    }

    /**
     * Gets token signature.
     *
     * @return String the token signature.
     */
    public String getSignature() {
        return signature;
    }

    /**
     * Set token signature.
     *
     * @param signature The token signature.
     */
    public void setSignature(String signature) {
        this.signature = signature;
    }

    /**
     * Gets signature method.
     *
     * @return String the signature method.
     */
    public String getSignatureMethod() {
        return signatureMethod;
    }

    /**
     * Set signature method.
     *
     * @param signatureMethod The signature method.
     */
    public void setSignatureMethod(String signatureMethod) {
        this.signatureMethod = signatureMethod;
    }

    /**
     * Gets user IP address.
     *
     * @return String the user ip address.
     */
    public String getUserAddress() {
        return userAddress;
    }

    /**
     * Set user ip address.
     *
     * @param userAddress The user ip address.
     */
    public void setUserAddress(String userAddress) {
        this.userAddress = userAddress;
    }

    /**
     * Gets corporative user.
     *
     * @return String the corporative user.
     */
    public String getUserCorp() {
        return userCorp;
    }

    /**
     * Set corporative user.
     *
     * @param userCorp The corporative user.
     */
    public void setUserCorp(String userCorp) {
        this.userCorp = userCorp;
    }

    /**
     * Gets user data.
     *
     * @return String the user data.
     */
    public Map<String, Object> getUserData() {
        return userData;
    }

    /**
     * Set user data.
     *
     * @param userData The user data.
     */
    public void setUserData(Map<String, Object> userData) {
        this.userData = userData;
    }

    /**
     * Gets user ID.
     *
     * @return String the user ID.
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Set user ID.
     *
     * @param userId The user ID.
     */
    public void setUserId(String userId) {
        this.userId = userId;
    }

    /**
     * Gets token version.
     *
     * @return String the token version.
     */
    public String getVersion() {
        return version;
    }

    /**
     * Set token version.
     *
     * @param version The token version.
     */
    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * Gets XML data.
     *
     * @return String the XML data.
     */
    public String getXmlData() {
        return xmlData;
    }

    /**
     * Set XML data.
     *
     * @param xmlData The XML data.
     */
    public void setXmlData(String xmlData) {
        this.xmlData = xmlData;
    }

    @Override
    public String toString() {
        final StringBuffer sb = new StringBuffer("BKSToken{");
        sb.append("originalData='").append(originalData).append('\'');
        sb.append(", securityId='").append(securityId).append('\'');
        sb.append(", userAddress='").append(userAddress).append('\'');
        sb.append(", expirationDate=").append(expirationDate);
        sb.append(", userData=").append(userData);
        sb.append(", userId='").append(userId).append('\'');
        sb.append(", userCorp='").append(userCorp).append('\'');
        sb.append(", localEmitter='").append(localEmitter).append('\'');
        sb.append(", xmlData='").append(xmlData).append('\'');
        sb.append(", cipherMethod='").append(cipherMethod).append('\'');
        sb.append(", version='").append(version).append('\'');
        sb.append(", emitter='").append(emitter).append('\'');
        sb.append(", encryptedXmlData='").append(encryptedXmlData).append('\'');
        sb.append(", signatureMethod='").append(signatureMethod).append('\'');
        sb.append(", signature='").append(signature).append('\'');
        sb.append('}');
        return sb.toString();
    }
//	@Override
//	public String toString() {
//		return new ToStringBuilder(this).append("originalData", originalData).append("securityId", securityId).append("userAddress", userAddress)
//				.append("expirationDate", expirationDate).append("userData", userData).append("userId", userId).append("userCorp", userCorp)
//				.append("localEmitter", localEmitter).append("xmlData", xmlData).append("cipherMethod", cipherMethod).append("version", version)
//				.append("emitter", emitter).append("encryptedXmlData", encryptedXmlData).append("signatureMethod", signatureMethod)
//				.append("signature", signature).toString();
//	}
}
