import '../lib/secretstore.dart';
import 'dart:convert';

const sk = "d104698a5c3bd61203a2c7fc74b68d8f7f021901e244fb9569c374989f24f3be";
const sk2 = "1bdee82116e6030d160cd7476e4a843f2c5fe16b3d4d41845676bc2d3277ca1e";
const hash = "df12206be1b54e52bcfa7c7dc1803201f20b30fac5a9f4b4dc492a68c04ddc90";
const serverKey = "807d030f0cad6141e4f5b1b528a7f55980a2b3145722feab94adcf85357560dd9f50e79f23f8a42a20721b97eafbca65bc71dfa7f87beb7d798d6776a66c8c1f";
const dec_secret = "28a327d0d97466952753f936570dd8db64c1deef955273ce5d94114d9c3bef4446301be68062d9507ae3cab65c1b75ebbcca377ce0cdd1cb404102bf96595805";
const common = "1eded924e3ed5b1c938f3f750e4c6eba27fcfd7a4be2d8e212c176a7a7ab705d5b630cd5ae5581a512ceb9de5c8785613c844aa8e8d8679f474ecda55a8326ab";
const chiper = "7484d19a644f60a24e22cc6ee78165588d6aed15ca10a8cb988bc9d9ec1ae2e123a45e";
const shadow1 = "04780078e77629bbdb5b7a09e6e83a9e66ef4070ccd908d9220ca05842c3275198fd709bfb3c7a5420c9b4061ccf16a88791e675e28bda4eeb73ada4e56c37b22e2cdc85e8b04d73a21d38aeb34ba7b86a16f294f0b99abf6048c222cd6dfb149d4b2becae1ec1aa845158540ab667b9c35202b0a4be8d58444ecb02e739ed0de92baa0221f576960e5ba2c9e5df64a0e4";
const shadow2 = "04dae157f57242de4f4fd76c7b7fd6cb36f8a8c8d8c8d6ff0d2c1dea2ffcdaa80516a209110c1449dec0ffb0286cececc8edb72ae75ab96ff9e1a6803b5cd9df82ca6682c1975ff3315d760bc2f44e003a83b645474fb458426eaf38369378c4ae504530442b20fe3717a64956a356015e6f9ebd8b423e70cc68790053b4189f40a8bd4c15a1e5d79a6d2800950f05c4f9";

main() {
  final ss = SecretStore();
  final sign = ss.signHash(sk, hash);
  print(sign);

  final eset = ss.getDocumentKey(sk, serverKey);
  print(eset.encrypted_key);

  final str = "Sahal Arafat Zain";
  final bstr = Utf8Encoder().convert(str);
  final hexData = bytesToHex(bstr);

  final enc = ss.encryptDocument(sk, eset.encrypted_key, hexData);
  print(enc);

  var shadows = List<String>();
  shadows.add(shadow1);
  shadows.add(shadow2);

  final dec = ss.decryptDocument(sk2, dec_secret, common, shadows, 2, chiper);
  print(dec);
  final res = Utf8Decoder().convert(hexToBytes(dec));
  print(res);
}