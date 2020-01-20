import 'dart:ffi';
import 'types.dart';
import 'package:ffi/ffi.dart';

typedef sign_hash = Pointer<Utf8> Function(Pointer<Utf8> secret,Pointer<Utf8> hash);
typedef shared_secret = Pointer<Utf8> Function(Pointer<Utf8> public,Pointer<Utf8> secret);
typedef get_document_key = Pointer<DocumentKey> Function(Pointer<Utf8> secret,Pointer<Utf8> serverKey);
typedef encrypt = Pointer<Utf8> Function(Pointer<Utf8> secret, Pointer<Utf8> key, Pointer<Utf8> data);
typedef decrypt_shadow = Pointer<Utf8> Function(Pointer<Utf8> secret, Pointer<Utf8> decrypted_secret, Pointer<Utf8> common_point, Pointer<Pointer<Utf8>> shadows, Uint32 len, Pointer<Utf8> data);
typedef decrypt_key = Pointer<Utf8> Function(Pointer<Utf8> secret, Pointer<Utf8> decrypted_secret, Pointer<Utf8> common_point, Pointer<Pointer<Utf8>> shadows, Uint32 len);
typedef decrypt_doc = Pointer<Utf8> Function(Pointer<Utf8> key, Pointer<Utf8> data);
typedef DecryptShadow = Pointer<Utf8> Function(Pointer<Utf8> secret, Pointer<Utf8> decrypted_secret, Pointer<Utf8> common_point, Pointer<Pointer<Utf8>> shadows, int len, Pointer<Utf8> data);
typedef DecryptKey = Pointer<Utf8> Function(Pointer<Utf8> secret, Pointer<Utf8> decrypted_secret, Pointer<Utf8> common_point, Pointer<Pointer<Utf8>> shadows, int len);