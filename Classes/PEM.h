#import <ObjFW/OFObject.h>

@class OFString;
@class OFArray;
@class OFDataArray;

@interface MBEDPEM: OFObject
{

}

+ (OFArray *)parsePEMString:(OFString *)pem header:(OFString *)header footer:(OFString *)footer password:(OFString *)password;

@end