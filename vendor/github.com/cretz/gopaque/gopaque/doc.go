/*
Package gopaque implements the OPAQUE protocol. The OPAQUE protocol, described
as of this writing in the RFC draft at
https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-01, is a protocol that
allows a user with a password to register and authenticate with a server without
ever giving that server the password. It uses the OPAQUE password authenticated
key exchange (PAKE) which uses derived keys for registration authentication. A
high-level introduction to OPAQUE (and PAKEs in general) is available at
https://blog.cryptographyengineering.com/2018/10/19/lets-talk-about-pake/.

This implementation uses the https://github.com/dedis/kyber crypto library.
The implementation is intentionally very extensible and exposed, but sensible
default implementations are provided for every abstraction. The registration and
authentication flows are below, followed by a couple of code examples clarifying
usage.

Warning

This was developed by a hobbyist, not a cryptographer. The code has not been
reviewed for accuracy or security. No care was taken to obfuscate the errors or
prevent timing attacks. Only use after reviewing the code and understanding the
implications.

Registration Flow

OPAQUE registration is a 3-message process starting with the user where a user
registers with the server. The only input a user needs is the password and after
registration, the server has the info to perform authentication.

The steps for a user are:

1 - Create a NewUserRegister with the user ID

2 - Call Init with the password and send the resulting UserRegisterInit to the
server

3 - Receive the server's ServerRegisterInit

4 - Call Complete with the server's ServerRegisterInit and send the resulting
UserRegisterComplete to the server

The steps for a server are:

1 - Receive the user's UserRegisterInit

2 - Create a NewServerRegister with a private key

3 - Call Init with the user's UserRegisterInit and send the resulting
ServerRegisterInit to the user

4 - Receive the user's UserRegisterComplete

5 - Call Complete with the user's UserRegisterComplete and persist the resulting
ServerRegisterComplete

Authentication Flow

OPAQUE authentication is intended to be used in conjunction with a key exchange
protocol to authenticate a user. Gopaque supports either an external key
exchange protocol or one embedded into the auth process. The pure OPAQUE part of
the flow is only a 2-message process, but validation with a key exchange often
adds a third message. The steps below assume the key exchange is embedded in
the auth process instead of being external.

The steps for a user are:

1 - Create a NewUserAuth with an embedded key exchange

2 - Call Init with the password and send the resulting UserAuthInit to the
server

3 - Receive the server's ServerAuthComplete

4 - Call Complete with the server's ServerAuthComplete. The resulting
UserAuthFinish has user and server key information. This would be the last step
if we were not using an embedded key exchange. Since we are, take the resulting
UserAuthComplete and send it to the server.

The steps for a server are:

1 - Receive the user's UserAuthInit

2 - Create a NewServerAuth with an embedded key exchange

3 - Call Complete with the user's UserAuthInit and persisted
ServerRegisterComplete and send the resulting ServerAuthComplete to the user.
This would be the last step if we were not using an embedded key exchange.

4 - Receive the user's UserAuthComplete

5 - Call Finish with the user's UserAuthComplete
*/
package gopaque
