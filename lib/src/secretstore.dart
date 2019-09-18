import 'binding.dart';
import 'types.dart';
import 'dart:ffi';
import 'dart:io';

String _platformPath(String name, {String path}) {
  if (path == null) path = "";
  if (Platform.isLinux || Platform.isAndroid)
    return path + "lib" + name + ".so";
  if (Platform.isMacOS) return path + "lib" + name + ".dylib";
  if (Platform.isWindows) return path + name + ".dll";
  throw Exception("Platform not implemented");
}

DynamicLibrary dlopenPlatformSpecific(String name, {String path}) {
  String fullPath = _platformPath(name, path: path);
  return DynamicLibrary.open(fullPath);
}

class EncryptedDocumentKey {
  String common_point;

  String encrypted_point;

  String encrypted_key;

  EncryptedDocumentKey(this.common_point, this.encrypted_point, this.encrypted_key);
}

class SecretStore {
  DynamicLibrary dylib;
  Pointer<Utf8> Function(Pointer<Utf8> secret,Pointer<Utf8> hash) _signHash;
  Pointer<DocumentKey> Function(Pointer<Utf8> secret,Pointer<Utf8> _serverKey) _getDocumentKey;
  Pointer<Utf8> Function(Pointer<Utf8> secret, Pointer<Utf8> key, Pointer<Utf8> data) _encryptDoc;
  Pointer<Utf8> Function(Pointer<Utf8> secret, Pointer<Utf8> decrypted_secret, Pointer<Utf8> common_point, Pointer<Pointer<Utf8>> shadows, int len, Pointer<Utf8> data) _decryptShadow;
  
  SecretStore() {
    dylib = dlopenPlatformSpecific('secretstore');
    final signHashPtr = dylib.lookup<NativeFunction<sign_hash>>('sign_hash');
    _signHash = signHashPtr.asFunction<sign_hash>();

    final docKeyPtr = dylib.lookup<NativeFunction<get_document_key>>('get_document_key');
    _getDocumentKey = docKeyPtr.asFunction<get_document_key>();

    final encryptPtr = dylib.lookup<NativeFunction<encrypt>>('encrypt');
    _encryptDoc = encryptPtr.asFunction<encrypt>();

    final decryptPtr = dylib.lookup<NativeFunction<decrypt_shadow>>('decrypt_shadow');
    _decryptShadow = decryptPtr.asFunction<DecryptShadow>();
  }

  String signHash(String secret, String hash) {
    final pSecret = Utf8.toUtf8(secret);
    final pHash = Utf8.toUtf8(hash);
    final sign = _signHash(pSecret, pHash);
    final res = Utf8.fromUtf8(sign);
    pSecret.free();
    pHash.free();
    sign.free();
    return res;
  }

  EncryptedDocumentKey getDocumentKey(String secret, String public) {
    final pSecret = Utf8.toUtf8(secret);
    final pPublic = Utf8.toUtf8(public);
    final esetPtr = _getDocumentKey(pSecret, pPublic );
    final eset = esetPtr.load<DocumentKey>();
    final enckey = Utf8.fromUtf8(eset.encrypted_key);
    final common = Utf8.fromUtf8(eset.common_point);
    final encpoint = Utf8.fromUtf8(eset.encrypted_point);
    esetPtr.free();
    pSecret.free();
    pPublic.free();
    return EncryptedDocumentKey(common, encpoint, enckey);
  }

  String encryptDocument(String secret, String key, String hexData) {
    final pSecret = Utf8.toUtf8(secret);
    final pKey = Utf8.toUtf8(key);
    final pData = Utf8.toUtf8(hexData);
    final pEnc = _encryptDoc(pSecret,pKey , pData);
    final res = Utf8.fromUtf8(pEnc);
    pSecret.free();
    pKey.free();
    pData.free();
    pEnc.free();
    return res;
  }

  String decryptDocument(String secret, String decrypt_secret, String common, List<String> shadows, int len, String hexData) {
    final shadowArr = Pointer<Pointer<Utf8>>.allocate(count: shadows.length);
    for (int i=0; i< shadows.length; i++) {
      shadowArr.elementAt(i).store(Utf8.toUtf8(shadows[i]));
    }
    final pSecret = Utf8.toUtf8(secret);
    final pDs = Utf8.toUtf8(decrypt_secret);
    final pCommon = Utf8.toUtf8(common);
    final pData = Utf8.toUtf8(hexData);
    final pDec = _decryptShadow(pSecret, pDs, pCommon, shadowArr, shadows.length, pData);
    final res = Utf8.fromUtf8(pDec);
    shadowArr.free();
    pDec.free();
    pSecret.free();
    pDs.free();
    pCommon.free();
    pData.free();
    return res;
  }
}