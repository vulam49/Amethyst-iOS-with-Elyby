#import <Security/Security.h>
#import <Security/Security.h>
#import "BaseAuthenticator.h"
#import "ElyByAuthenticator.h"
#import "../LauncherPreferences.h"
#import "../ios_uikit_bridge.h"
#import "../utils.h"

@implementation BaseAuthenticator

static BaseAuthenticator *current = nil;

+ (id)current {
    if (current == nil) {
        [self loadSavedName:getPrefObject(@"internal.selected_account")];
    }
    return current;
}

+ (void)setCurrent:(BaseAuthenticator *)auth {
    current = auth;
}

+ (id)loadSavedName:(NSString *)name {
    NSMutableDictionary *authData = parseJSONFromFile([NSString stringWithFormat:@"%s/accounts/%@.json", getenv("POJAV_HOME"), name]);
    if (authData[@"NSErrorObject"] != nil) {
        NSError *error = ((NSError *)authData[@"NSErrorObject"]);
        if (error.code != NSFileReadNoSuchFileError) {
            showDialog(localize(@"Error", nil), error.localizedDescription);
        }
        return nil;
    }

    // Check accountType first so Ely.by accounts are never
    // confused with Microsoft accounts (both have expiresAt != 0).
    if ([authData[@"accountType"] isEqualToString:@"Ely.by"]) {
        return [[ElyByAuthenticator alloc] initWithData:authData];
    } else if ([authData[@"expiresAt"] longValue] == 0) {
        return [[LocalAuthenticator alloc] initWithData:authData];
    } else {
        return [[MicrosoftAuthenticator alloc] initWithData:authData];
    }
}

- (id)initWithData:(NSMutableDictionary *)data {
    current = self = [self init];
    self.authData = data;
    return self;
}

- (id)initWithInput:(NSString *)string {
    NSMutableDictionary *data = [[NSMutableDictionary alloc] init];
    data[@"input"] = string;
    return [self initWithData:data];
}

- (void)loginWithCallback:(Callback)callback {
}

- (void)refreshTokenWithCallback:(Callback)callback {
}

- (BOOL)saveChanges {
    NSError *error;

    [self.authData removeObjectForKey:@"input"];

    NSString *newPath = [NSString stringWithFormat:@"%s/accounts/%@.json", getenv("POJAV_HOME"), self.authData[@"username"]];
    if (self.authData[@"oldusername"] != nil && ![self.authData[@"username"] isEqualToString:self.authData[@"oldusername"]]) {
        NSString *oldPath = [NSString stringWithFormat:@"%s/accounts/%@.json", getenv("POJAV_HOME"), self.authData[@"oldusername"]];
        [NSFileManager.defaultManager moveItemAtPath:oldPath toPath:newPath error:&error];
        // handle error?
    }

    [self.authData removeObjectForKey:@"oldusername"];

    error = saveJSONToFile(self.authData, newPath);

    if (error != nil) {
        showDialog(@"Error while saving file", error.localizedDescription);
    }
    return error == nil;
}

@end

@implementation BaseAuthenticator (TokenData)

+ (NSDictionary *)tokenDataOfProfile:(NSString *)profile {
    if (!profile) return nil;
    NSDictionary *query = @{
        (id)kSecClass:       (id)kSecClassGenericPassword,
        (id)kSecAttrService: @"AccountToken",
        (id)kSecAttrAccount: profile,
        (id)kSecReturnData:  @YES,
        (id)kSecMatchLimit:  (id)kSecMatchLimitOne
    };
    CFDataRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query,
                                          (CFTypeRef *)&result);
    if (status != errSecSuccess || !result) return nil;
    NSData *data = (__bridge_transfer NSData *)result;
    return [NSKeyedUnarchiver unarchivedObjectOfClass:[NSDictionary class]
                                            fromData:data
                                               error:nil];
}

@end
