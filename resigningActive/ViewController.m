//
//  ViewController.m
//  resigningActive
//
//  Created by William Gray on 8/5/21.
//

#import "ViewController.h"
#import <Security/Security.h>

@interface ViewController ()
@property (nonatomic, strong) IBOutlet UILabel *statusLabel;
- (IBAction)installSecret:(id)sender;
- (IBAction)promptForSecret:(id)sender;
- (IBAction)removeSecret:(id)sender;
+ (NSMutableDictionary *)queryDictionary:(NSError **)error;
+ (SecAccessControlRef)createAccessControlReference:(NSError **)error;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
}

//- (void)viewDidAppear:(BOOL)animated {
//    [super viewDidAppear:animated];
//
//}

- (IBAction)installSecret:(id)sender {
    OSStatus status;
    NSData *secret = [@"42" dataUsingEncoding:NSUTF8StringEncoding];
    NSError *dictError;
    NSMutableDictionary *query = [[self class] queryDictionary:&dictError];
    [query addEntriesFromDictionary:@{
        (__bridge id)kSecValueData: secret,
    }];
    status = SecItemAdd((__bridge CFDictionaryRef)query, nil);
    if (status == errSecSuccess) {
        self.statusLabel.text = @"Secret installed to Keychain.";
    } else {
        self.statusLabel.text = [NSString stringWithFormat:@"Already installed? Error code: %d", (int)status];
    }
}

- (IBAction)promptForSecret:(id)sender {
    NSMutableDictionary *query = [[self class] queryDictionary:nil];
    [query addEntriesFromDictionary:@{
        (__bridge id)kSecReturnData: @(YES),
//        (__bridge id)kSecUseOperationPrompt: @"Authenticate (or cancel) to kick off the resign active issue"
    }];
    CFTypeRef dataTypeRef = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &dataTypeRef);
    if (status == errSecSuccess) {
        NSData *resultData = (__bridge NSData *)dataTypeRef;
        NSString *secret = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
        self.statusLabel.text = [NSString stringWithFormat:@"The Secret to LTU&E: %@", secret];
    } else if (status == errSecUserCanceled) {
        self.statusLabel.text = @"Prompt cancelled.";
    } else {
        self.statusLabel.text = [NSString stringWithFormat:@"Keychain lookup failed. Error code: %d", (int)status];
    }
}

- (IBAction)removeSecret:(id)sender {
    NSMutableDictionary *query = [[self class] queryDictionary:nil];
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)(query));
    if (status == errSecSuccess) {
        self.statusLabel.text = @"Secret removed from Keychain";
    } else {
        self.statusLabel.text = [NSString stringWithFormat:@"Delete from Keychain failed. Error code: %d", (int)status];
    }
}

+ (SecAccessControlRef)createAccessControlReference:(NSError **)error {
    SecAccessControlRef sacRef = NULL;
    CFErrorRef errorRef = NULL;
    
    sacRef = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                             kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                             kSecAccessControlBiometryCurrentSet,
                                             &errorRef);
    
    if (sacRef == NULL || errorRef != NULL) {
        if (error != NULL) {
            *error = (__bridge NSError *)errorRef;
        }
    }
    return sacRef;
}

+ (NSMutableDictionary *)queryDictionary:(NSError **)error {
    SecAccessControlRef sacObject;
    // prepare Security Access Control flags - secret should be invalidated when passcode is removed
    sacObject = [self createAccessControlReference:error];
    if (sacObject == NULL) {
        NSLog(@"Unable to create security access control, check that device passcode is set and Touch ID is available");
        return nil;
    }
    NSDictionary *base = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"net.zetetic.resignActive",
        (__bridge id)kSecAttrAccessControl: (__bridge id)sacObject,
        (__bridge id)kSecAttrAccount: @"resignActive stored secret"
    };
    CFRelease(sacObject);
    return [NSMutableDictionary dictionaryWithDictionary:base];
}

@end
