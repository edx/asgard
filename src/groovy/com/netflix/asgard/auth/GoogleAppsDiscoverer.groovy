package com.netflix.asgard.auth

import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.discovery.Discovery;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.discovery.UrlIdentifier;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * {@link OpenIdSsoSecurityRealm} with Google Apps.
 *
 * @author Kohsuke Kawaguchi
 */
public class GoogleAppsDiscoverer {
	public final String domain;

	public GoogleAppsDiscoverer(String domain) throws IOException, OpenIDException {
		//super("https://www.google.com/accounts/o8/site-xrds?hd="+domain);
		this.domain = domain;
	}

	@Override
	protected ConsumerManager createManager() throws ConsumerException {
		ConsumerManager m = new ConsumerManager();
		m.setDiscovery(new Discovery() {
			/**
			 * See http://www.slideshare.net/timdream/google-apps-account-as-openid for more details
			 * why this is needed. Basically, once Google reports back that the user is actually http://mycorp.com/openid?id=12345,
			 * the consumer still needs to try to resolve this ID to make sure that Google didn't return a bogus address
			 * (say http://whitehouse.gov/barack_obama). This fails unless the web server of mycorp.com handles
			 * GET to http://mycorp.com/openid?id=12345 properly, (which it doesn't most of the time.)
			 *
			 * The actual resource is in https://www.google.com/accounts/o8/user-xrds?uri=http://mycorp.com/openid?id=12345
			 * so does Yadris lookup on that URL and pretend as if that came from http://mycorp.com/openid?id=12345
			 */
			@Override
			public List discover(Identifier id) throws DiscoveryException {
				if (id.getIdentifier().startsWith("http://"+domain+'/') && id instanceof UrlIdentifier) {
					String source = "https://www.google.com/accounts/o8/user-xrds?uri=" + id.getIdentifier();
					List<DiscoveryInformation> r = super.discover(new UrlIdentifier(source));
					List<DiscoveryInformation> x = new ArrayList<DiscoveryInformation>();
					for (DiscoveryInformation discovered : r) {
						if (discovered.getClaimedIdentifier().getIdentifier().equals(source)) {
							discovered = new DiscoveryInformation(discovered.getOPEndpoint(),
									id,
									discovered.getDelegateIdentifier(),
									discovered.getVersion(),
									discovered.getTypes()
							);
						}
						x.add(discovered);
					}
					return x;
				}
				return super.discover(id);
			}
		});
		return m;
	}

}