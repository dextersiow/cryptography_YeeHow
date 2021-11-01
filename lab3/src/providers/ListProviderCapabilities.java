package providers;

import java.security.Provider;
import java.security.Security;
import java.util.Iterator;

public class ListProviderCapabilities {

	public static void main(final String[] args) {
		// We provide the name of a provider we are interested in.
		final Provider provider = Security.getProvider("SunEC");

		// We iterate through everything provided by the provider, e.g., key
		// generators, algorithms or ciphers, etc.
		for (final Iterator<Object> it = provider.keySet().iterator(); it
				.hasNext();) {
			final String entry = (String) it.next();

			if (entry.startsWith("Alg.Alias")) {
				continue; // We can skip "aliases".
			}

			// For each entry we print its type (or "serviceName") and its name
			// ("name").
			final String serviceName = entry.substring(0, entry.indexOf('.'));
			final String name = entry.substring(serviceName.length() + 1);
			System.out.println(serviceName + ": " + name);
		}
	}
}