#import <ObjFW/OFObject.h>

@class OFString;
@class OFDataArray;

@protocol X509Object <OFObject>

@property (copy, readonly)OFString* PEM;

@property (copy, readonly)OFDataArray* DER;

- (void)parsePEMorDER:(OFDataArray *)data password:(_Nullable OFString *)password;

- (void)parsePEM:(OFString *)pem;

- (void)parseDER:(OFDataArray *)der;

- (void)parseFile:(OFString *)fileName;

- (void)parseFilesAtPath:(OFString *)path;

@end