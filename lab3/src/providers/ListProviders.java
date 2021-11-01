package providers;

import java.security.Provider;
import java.security.Security;

public class ListProviders {

	public static void main(final String[] args) {
		// We get a list of the providers and store them in an array.
		final Provider[] providers = Security.getProviders();

		// We iterate through each provider in the array and print their names
		// and information.
		for (final Provider provider : providers) {
			System.out.print(provider.getName());
			System.out.print(": ");
			System.out.print(provider.getInfo());
			System.out.println();
		}
	}
}