package providers;
import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
public class ListProvidersWithBC {
	static {
		// We add Bouncy Castle as a provider.
		Security.addProvider(new BouncyCastleProvider());
	}
	public static void main(final String[] args) {
		// We get a list of the providers and store them in an array.
		final Provider[] providers = Security.getProviders();
		// We iterate through each provider in the array and print its name and
		// information. Note the inclusion of the "BC" (Bouncy Castle) provider.
		for (final Provider provider : providers) {
			System.out.print(provider.getName());
			System.out.print(": ");
			System.out.print(provider.getInfo());
			System.out.println();
		}
	}
}