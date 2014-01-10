package com.netflix.asgard.auth

import javax.servlet.http.HttpServletRequest

import org.apache.shiro.authc.AuthenticationInfo;

import com.amazonaws.services.simpleemail.model.transform.GetIdentityVerificationAttributesResultStaxUnmarshaller.VerificationAttributesMapEntryUnmarshaller;
import com.netflix.asgard.plugin.AuthenticationProvider;

import org.apache.shiro.SecurityUtils
import org.apache.shiro.authc.AuthenticationException
import org.apache.shiro.authc.RememberMeAuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo
import org.apache.shiro.authc.UsernamePasswordToken
import org.apache.shiro.web.util.SavedRequest
import org.apache.shiro.web.util.WebUtils
import org.apache.shiro.grails.ConfigUtils
import org.openid4java.consumer.ConsumerManager
import org.openid4java.discovery.DiscoveryInformation
import org.openid4java.discovery.DiscoveryException
import org.openid4java.message.AuthRequest
import org.openid4java.message.AuthSuccess
import org.openid4java.message.ax.FetchRequest
import org.openid4java.message.ax.FetchResponse
import org.openid4java.message.ax.AxMessage
import org.openid4java.util.ProxyProperties
import org.openid4java.util.HttpClientFactory
import org.openid4java.message.ParameterList
import org.openid4java.message.Parameter
import org.openid4java.consumer.VerificationResult
import org.openid4java.discovery.Identifier
import org.springframework.aop.aspectj.RuntimeTestWalker.ThisInstanceOfResidueTestVisitor;
import org.springframework.beans.factory.annotation.Autowired;
import org.apache.shiro.crypto.hash.Sha256Hash

import com.netflix.asgard.ConfigService;
import com.netflix.asgard.Role;
import com.netflix.asgard.User

import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.discovery.Discovery;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.discovery.UrlIdentifier;

class GoogleAppsOpenIdAuthenticationProvider implements AuthenticationProvider {

	static final String verificationURLTemplate="https://www.google.com/accounts/o8/user-xrds?uri="

	@Autowired
	ConfigService configService

	static ConsumerManager consumerManager = null

	static ConsumerManager getManager() {
		if (! consumerManager)
			consumerManager = new ConsumerManager()
		consumerManager.setDiscovery(new Discovery() {
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
						if (id.getIdentifier().startsWith("http://edx.org/") && id instanceof UrlIdentifier) {
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
		return consumerManager
	}

	@Override
	public String loginUrl(HttpServletRequest request) {
		return "https://www.google.com/a/edx.org/o8/ud" +
		"?be=o8" + 
		"&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0" +
		"&openid.mode=checkid_setup" +
		"&openid.claimed_id=https%3A%2F%2Fwww.google.com%2Faccounts%2Fo8%2Fsite-xrds%3Fhd%3Dedx.org" +
		"&openid.identity=https%3A%2F%2Fwww.google.com%2Faccounts%2Fo8%2Fsite-xrds%3Fhd%3Dedx.org" + 
		"&openid.return_to=" + java.net.URLEncoder.encode(configService.getCanonicalServerName(),'UTF-8') + 
		"&openid.ns.ax=http%3A%2F%2Fopenid.net%2Fsrv%2Fax%2F1.0" +
		"&openid.ax.mode=fetch_request" +
		"&openid.ax.required=email%2CfirstName%2ClastName" +
		"&openid.ax.type.email=http%3A%2F%2Fschema.openid.net%2Fcontact%2Femail" +
		"&openid.ax.type.firstName=http%3A%2F%2Faxschema.org%2FnamePerson%2Ffirst" +
		"&openid.ax.type.lastName=http%3A%2F%2Faxschema.org%2FnamePerson%2Flast" + 
		"&openid.ns.ext2=http%3A%2F%2Fspecs.openid.net%2Fextensions%2Fui%2F1.0" + 
		"&openid.ext2.icon=true"
	}

	@Override
	public String logoutUrl(HttpServletRequest request) {
		return "https://www.google.com/accounts/Logout";
	}

	@Override
	public AsgardToken tokenFromRequest(HttpServletRequest request) {
		// extract the parameters from the authentication response
		// (which comes in as a HTTP request from the OpenID provider)
		ParameterList openidResp = new ParameterList(request.getParameterMap())

		def session = request.getSession()
		def params = request.getParameterMap()

		// retrieve the previously stored discovery information
		DiscoveryInformation discovered = (DiscoveryInformation) request.getSession().getAttribute("discovered")

		// extract the receiving URL from the HTTP request
		URI url = new URI(request.getRequestURL() as String)	
		String receivingURL = url.scheme + "://" + url.authority + request.forwardURI
		String queryString = request.queryString
		if (queryString != null && queryString.length() > 0)
			receivingURL = receivingURL + "?" + queryString

		// verify the response
		VerificationResult verification = manager.verify(receivingURL.toString(), openidResp, discovered)

		// examine the verification result and extract the verified identifier
		Identifier verified = verification.verifiedId

		// Support for "remember me"
		if (params.rememberMe) {
			authToken.rememberMe = true
		}

		if (verified == null)
			throw new AuthenticationException()

		def username = verified.identifier
		AuthSuccess authSuccess = (AuthSuccess) verification.getAuthResponse()
		if (authSuccess.hasExtension(AxMessage.OPENID_NS_AX)) {
			FetchResponse fetchResp = (FetchResponse) authSuccess.getExtension(AxMessage.OPENID_NS_AX)
			List emails = fetchResp.getAttributeValues("email")
			username = emails[0]
		}

		if (! configService.getAdministrators().contains(username))
			throw new AuthenticationException("User ${username} is not on the whitelist")

		if (! User.findByUsername(username)) {
			def user = new User(username: username, passwordHash: new Sha256Hash(User.defaultPass).toHex())
			user.addToRoles(Role.adminRole)
			user.save(flush: true)
		}

		GoogleAppsOpenIdToken token = new GoogleAppsOpenIdToken(verified,username)

		return token
	}

	@Override
	AuthenticationInfo authenticate(AsgardToken authToken) {
		GoogleAppsOpenIdToken token = (GoogleAppsOpenIdToken) authToken

		if (token == null) {
			throw new AuthenticationException('Google Apps OpenID token cannot be null')
		}
		if (!token.valid) {
			throw new AuthenticationException('Invalid Google Apps OpenId token')
		}

		new SimpleAuthenticationInfo(token.principal, token.credentials, 'GoogleAppsOpenIdRealm')
	}



	class GoogleAppsOpenIdToken implements AsgardToken, RememberMeAuthenticationToken {

		Object credentials
		String principal
		boolean valid = false

		public GoogleAppsOpenIdToken(Object credentials, String principal) {
			this.credentials = credentials
			this.principal = principal
			this.valid = true
		}

		@Override
		public Object getCredentials() {
			return this.credentials
		}

		@Override
		public Object getPrincipal() {
			return this.principal
		}

		public isValid() {
			return this.valid
		}

		@Override
		public boolean isRememberMe() {
			return true;
		}

	}

}
