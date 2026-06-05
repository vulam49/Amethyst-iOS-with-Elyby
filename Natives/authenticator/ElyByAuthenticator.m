#import <Security/Security.h>
#import "ElyByAuthenticator.h"
#import "BaseAuthenticator.h"
#import "../ios_uikit_bridge.h"
#import "../utils.h"

@implementation ElyByAuthenticator

#pragma mark - Keychain

- (BOOL)saveAccessToken:(NSString *)accessToken {
    if (!accessToken) return NO;
    NSString *xuid = self.authData[@"xuid"];
    if (!xuid) return NO;

    NSData *data = [NSKeyedArchiver archivedDataWithRootObject:@{
        @"accessToken": accessToken,
        @"refreshToken": accessToken,
    } requiringSecureCoding:YES error:nil];

    NSDictionary *query = @{
        (id)kSecClass:          (id)kSecClassGenericPassword,
        (id)kSecAttrService:    @"AccountToken",
        (id)kSecAttrAccount:    xuid,
        (id)kSecAttrAccessible: (id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        (id)kSecValueData:      data
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
    return SecItemAdd((__bridge CFDictionaryRef)query, NULL) == errSecSuccess;
}

#pragma mark - Network helper

- (NSDictionary *)postToPath:(NSString *)path
                        body:(NSDictionary *)body
                       error:(NSError **)outError {
    NSURL *url = [NSURL URLWithString:[@"https://authserver.ely.by" stringByAppendingString:path]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [req setValue:@"application/json" forHTTPHeaderField:@"Accept"];
    req.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];

    __block NSData *responseData = nil;
    __block NSURLResponse *responseObj = nil;
    __block NSError *networkError = nil;

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    [[NSURLSession.sharedSession dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            responseData = d;
            responseObj  = r;
            networkError = e;
            dispatch_semaphore_signal(sem);
    }] resume];
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

    if (networkError) {
        if (outError) *outError = networkError;
        return nil;
    }

    NSInteger status = ((NSHTTPURLResponse *)responseObj).statusCode;
    NSDictionary *json = nil;
    if (responseData.length > 0) {
        json = [NSJSONSerialization JSONObjectWithData:responseData
                                              options:0
                                                error:nil];
    }

    if (status >= 200 && status < 300) return json;

    NSString *msg = json[@"errorMessage"] ?: json[@"error"]
        ?: [NSHTTPURLResponse localizedStringForStatusCode:status];
    if (outError) {
        *outError = [NSError errorWithDomain:@"ElyByAuthenticator"
                                        code:status
                                    userInfo:@{NSLocalizedDescriptionKey: msg}];
    }
    return nil;
}

#pragma mark - Parse auth response

- (BOOL)applyAuthResponse:(NSDictionary *)json error:(NSError **)outError {
    NSString *accessToken = json[@"accessToken"];
    NSDictionary *profile = json[@"selectedProfile"];
    if (!profile) {
        profile = [json[@"availableProfiles"] firstObject];
    }

    if (!accessToken || !profile) {
        if (outError) {
            *outError = [NSError errorWithDomain:@"ElyByAuthenticator"
                                            code:-1
                                        userInfo:@{NSLocalizedDescriptionKey:
                            @"Ely.by returned an empty profile. "
                             "Make sure your account has a character."}];
        }
        return NO;
    }

    NSString *rawId = profile[@"id"] ?: @"";
    NSString *xuid = [[rawId componentsSeparatedByString:@"-"]
                            componentsJoinedByString:@""];

    NSString *profileId = rawId;
    if (rawId.length == 32) {
        profileId = [NSString stringWithFormat:@"%@-%@-%@-%@-%@",
            [rawId substringWithRange:NSMakeRange( 0,  8)],
            [rawId substringWithRange:NSMakeRange( 8,  4)],
            [rawId substringWithRange:NSMakeRange(12,  4)],
            [rawId substringWithRange:NSMakeRange(16,  4)],
            [rawId substringWithRange:NSMakeRange(20, 12)]];
    }

    NSString *name = profile[@"name"] ?: @"";

    self.authData[@"oldusername"]   = self.authData[@"username"] ?: name;
    self.authData[@"username"]      = name;
    self.authData[@"profileId"]     = profileId;
    self.authData[@"xuid"]          = xuid;
    self.authData[@"accountType"]   = @"Ely.by";
    self.authData[@"profilePicURL"] = [NSString stringWithFormat:
        @"https://skinsystem.ely.by/skins/%@.png", name];
    self.authData[@"expiresAt"]     = @(4070908800L);

    if (![self saveAccessToken:accessToken]) {
        if (outError) {
            *outError = [NSError errorWithDomain:@"ElyByAuthenticator"
                                            code:-2
                                        userInfo:@{NSLocalizedDescriptionKey:
                            @"Failed to save access token to keychain."}];
        }
        return NO;
    }
    return YES;
}

#pragma mark - BaseAuthenticator overrides

- (void)loginWithCallback:(Callback)callback {
    NSString *input = self.authData[@"input"] ?: @"";
    NSRange sep = [input rangeOfString:@"\n"];
    if (sep.location == NSNotFound) {
        callback([NSError errorWithDomain:@"ElyByAuthenticator"
                                     code:-3
                                 userInfo:@{NSLocalizedDescriptionKey:
                     @"Invalid input format."}], NO);
        return;
    }
    NSString *username = [input substringToIndex:sep.location];
    NSString *password = [input substringFromIndex:sep.location + 1];

    callback(@"Connecting to Ely.by...", YES);

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError *error = nil;
        NSDictionary *json = [self postToPath:@"/auth/authenticate"
                                         body:@{
            @"agent":       @{@"name": @"Minecraft", @"version": @1},
            @"username":    username,
            @"password":    password,
            @"clientToken": @"AmethystiOS",
            @"requestUser": @YES
        } error:&error];

        if (error) {
            callback(error, NO);
            return;
        }

        if (![self applyAuthResponse:json error:&error]) {
            callback(error, NO);
            return;
        }

        BOOL saved = [self saveChanges];
        if (saved) {
            // Download authlib-injector synchronously so it's
            // guaranteed to be ready before the user hits Play
            [ElyByAuthenticator ensureAuthlibInjector];
        }
        callback(nil, saved);
    });
}

- (void)refreshTokenWithCallback:(Callback)callback {
    NSString *xuid = self.authData[@"xuid"];
    NSDictionary *stored = [MicrosoftAuthenticator tokenDataOfProfile:xuid];
    NSString *currentToken = stored[@"accessToken"];

    if (!currentToken) {
        callback(nil, YES);
        return;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSURL *url = [NSURL URLWithString:@"https://authserver.ely.by/auth/validate"];
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
        req.HTTPMethod = @"POST";
        [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        req.HTTPBody = [NSJSONSerialization dataWithJSONObject:
            @{@"accessToken": currentToken} options:0 error:nil];

        __block NSHTTPURLResponse *httpResp = nil;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        [[NSURLSession.sharedSession dataTaskWithRequest:req
            completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
                httpResp = (NSHTTPURLResponse *)r;
                dispatch_semaphore_signal(sem);
        }] resume];
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

        if (httpResp.statusCode == 204) {
            callback(nil, YES);
            return;
        }

        NSError *refreshErr = nil;
        NSDictionary *json = [self postToPath:@"/auth/refresh"
                                         body:@{
            @"accessToken": currentToken,
            @"clientToken": @"AmethystiOS"
        } error:&refreshErr];

        if (refreshErr) {
            callback(refreshErr, NO);
            return;
        }

        NSError *applyErr = nil;
        if (![self applyAuthResponse:json error:&applyErr]) {
            callback(applyErr, NO);
            return;
        }
        [self saveChanges];
        callback(nil, YES);
    });
}

- (BOOL)saveChanges {
    return [super saveChanges];
}

#pragma mark - authlib-injector bootstrap (synchronous — Fix 3)

+ (void)ensureAuthlibInjector {
    NSString *dest = [NSString stringWithFormat:@"%s/authlib-injector.jar",
                      getenv("POJAV_HOME")];

    // Delete if file is too small (corrupt partial download)
    NSDictionary *attrs = [NSFileManager.defaultManager
                           attributesOfItemAtPath:dest error:nil];
    if (attrs && [attrs[NSFileSize] longLongValue] < 100000) {
        [NSFileManager.defaultManager removeItemAtPath:dest error:nil];
        attrs = nil;
    }

    if (attrs) return; // Already downloaded and valid

    NSLog(@"[ElyBy] Downloading authlib-injector...");
    NSURL *src = [NSURL URLWithString:
        @"https://github.com/yushijinhun/authlib-injector"
         "/releases/latest/download/authlib-injector.jar"];

    // Synchronous download — ready before user can press Play
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    [[NSURLSession.sharedSession downloadTaskWithURL:src
        completionHandler:^(NSURL *location, NSURLResponse *r, NSError *e) {
            if (e || !location) {
                NSLog(@"[ElyBy] authlib-injector download failed: %@", e);
            } else {
                NSError *moveErr = nil;
                [NSFileManager.defaultManager moveItemAtURL:location
                                                      toURL:[NSURL fileURLWithPath:dest]
                                                      error:&moveErr];
                if (moveErr) {
                    NSLog(@"[ElyBy] authlib-injector move failed: %@", moveErr);
                } else {
                    NSLog(@"[ElyBy] authlib-injector saved to %@", dest);
                }
            }
            dispatch_semaphore_signal(sem);
    }] resume];
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
}

@end
