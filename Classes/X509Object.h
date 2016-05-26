#import <ObjFW/OFObject.h>

@class OFString;
@class OFDataArray;

@protocol X509Object <OFObject>

@property (copy, readonly)OFString* PEM;

@property (copy, readonly)OFDataArray* DER;

- (void)parsePEMorDER:(OFDataArray *)data password:(_Nullable OFString *)password;

- (void)parsePEMorDER:(OFDataArray *)data header:(OFString *)header footer:(OFString *)footer password:(_Nullable OFString *)password;

- (void)parsePEM:(OFString *)pem;

- (void)parseDER:(OFDataArray *)der;

- (void)parseFile:(OFString *)fileName;

- (void)parseFilesAtPath:(OFString *)path;

@end

@protocol X509ObjectsChain <OFObject>

@property OF_NULLABLE_PROPERTY (copy, readonly)id<X509Object> next;

@property (assign, readonly)size_t count;

@end


@interface X509Object: OFObject <X509Object>
{

}

/*
* Must be overwrited in child class
*
*- (void)parseDER:(OFDataArray *)der
*- (void)parseFile:(OFString *)fileName
*- (void)parsePEMorDER:(OFDataArray *)data password:(_Nullable OFString *)password
*
*
*
*/

@end