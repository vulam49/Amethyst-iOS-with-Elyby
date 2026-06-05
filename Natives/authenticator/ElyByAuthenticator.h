#import "BaseAuthenticator.h"

// Ely.by Yggdrasil-compatible auth endpoints
#define ELY_AUTH_BASE @"https://authserver.ely.by"
#define ELY_CLIENT_TOKEN @"AmethystiOS"

@interface ElyByAuthenticator : BaseAuthenticator

/// Downloads authlib-injector.jar to $POJAV_HOME if it isn't there yet.
/// Called automatically on first login. Safe to call multiple times.
+ (void)ensureAuthlibInjector;

@end
