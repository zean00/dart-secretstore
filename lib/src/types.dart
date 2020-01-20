import 'dart:ffi';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:ffi/ffi.dart';

class DocumentKey extends Struct {
  Pointer<Utf8> common_point;

  Pointer<Utf8> encrypted_point;

  Pointer<Utf8> encrypted_key;

  factory DocumentKey.allocate(
          Pointer<Utf8> common_point, Pointer<Utf8> encrypted_point, Pointer<Utf8> encrypted_key) =>
      allocate<DocumentKey>().ref
        ..common_point = common_point
        ..encrypted_point = encrypted_point
        ..encrypted_key = encrypted_key;
}

String strip0x(String hex) {
  if (hex.startsWith('0x')) return hex.substring(2);
  return hex;
}

String bytesToHex(List<int> bytes,
    {bool include0x = false,
    int forcePadLength,
    bool padToEvenLength = false}) {
  var encoded = hex.encode(bytes);

  if (forcePadLength != null) {
    assert(forcePadLength >= encoded.length);

    final padding = forcePadLength - encoded.length;
    encoded = ('0' * padding) + encoded;
  }

  if (padToEvenLength && encoded.length % 2 != 0) {
    encoded = '0$encoded';
  }

  return (include0x ? '0x' : '') + hex.encode(bytes);
}

/// Converts the hexadecimal string, which can be prefixed with 0x, to a byte
/// sequence.
Uint8List hexToBytes(String hexStr) {
  final bytes = hex.decode(strip0x(hexStr));
  if (bytes is Uint8List) return bytes;

  return Uint8List.fromList(bytes);
}