package io.github.tricatch.gotpache.tomcat;

import io.github.tricatch.gotpache.cert.CertificateKeyPair;
import io.github.tricatch.gotpache.cert.GotpacheCertException;
import io.github.tricatch.gotpache.cert.SSLCertificateCreator;
import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * It supports the Tomcat SSL connector.
 */
public class SSLConnector {

    public Connector create(X509Certificate caCertificate, PrivateKey caPrivateKey, List<String> domains, int port) throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException, GotpacheCertException {

        Http11NioProtocol protocolHandler = new Http11NioProtocol();
        protocolHandler.setPort(port);
        protocolHandler.setSSLEnabled(true);
        protocolHandler.setSecure(true);

        List<String> hostAliases = new ArrayList<>();
        hostAliases.add("_default_");
        hostAliases.addAll(domains);

        for(int i=0;i<hostAliases.size();i++){

            String alias  = hostAliases.get(i);
            SSLCertificateCreator sslCertificateCreator = new SSLCertificateCreator();
            CertificateKeyPair certificateKeyPair = sslCertificateCreator.generateSSLCertificate(alias, caCertificate, caPrivateKey);

            X509Certificate sslCertificate = certificateKeyPair.getCertificate();
            PrivateKey sslPrivateKey = certificateKeyPair.getPrivateKey();

            Certificate[] certChain = new Certificate[1];
            certChain[0] = sslCertificate;

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);

            keyStore.setKeyEntry(alias, sslPrivateKey, "password".toCharArray(), certChain);

            SSLHostConfig sslHostConfig = new SSLHostConfig();
            sslHostConfig.setHostName(alias);
            sslHostConfig.setProtocols("TLSv1.2,TLSv1.3");

            SSLHostConfigCertificate sslHostConfigCertificate =
                    new SSLHostConfigCertificate(sslHostConfig, SSLHostConfigCertificate.Type.RSA);

            sslHostConfigCertificate.setCertificateKeystore(keyStore);
            sslHostConfigCertificate.setCertificateKeystorePassword("password");

            sslHostConfig.addCertificate(sslHostConfigCertificate);

            protocolHandler.addSslHostConfig(sslHostConfig);
        }

        Connector connector = new Connector(protocolHandler);
        connector.setScheme("https");

        return connector;
    }

}
