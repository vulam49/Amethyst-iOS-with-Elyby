#import "Foundation/Foundation.h"

typedef void(^Callback)(id status, BOOL success);

@interface BaseAuthenticator : NSObject

@property(class) BaseAuthenticator *current;

@property NSMutableDictionary *authData;

+ (id)loadSavedName:(NSString *)name;
+ (NSDictionary *)tokenDataOfProfile:(NSString *)profile;

- (id)initWithInput:(NSString *)string;
- (void)loginWithCallback:(Callback)callback;
- (void)refreshTokenWithCallback:(Callback)callback;
- (BOOL)saveChanges;

@end

@interface LocalAuthenticator : BaseAuthenticator
@end

@interface MicrosoftAuthenticator : BaseAuthenticator

+ (void)clearTokenDataOfProfile:(NSString *)profile;

@end

@interface ElyByAuthenticator : BaseAuthenticator

/// Downloads authlib-injector.jar to $POJAV_HOME if not already present.
/// Called automatically after a successful Ely.by login.
+ (void)ensureAuthlibInjector;

@end
