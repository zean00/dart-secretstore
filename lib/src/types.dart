import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';
import 'package:convert/convert.dart';

class Utf8 extends Struct<Utf8> {
  @Uint8()
  int char;

  static String fromUtf8(Pointer<Utf8> ptr) {
    final units = List<int>();
    var len = 0;
    while (true) {
      final char = ptr.elementAt(len++).load<Utf8>().char;
      if (char == 0) break;
      units.add(char);
    }
    return Utf8Decoder().convert(units);
  }

  static Pointer<Utf8> toUtf8(String s) {
    final units = Utf8Encoder().convert(s);
    final ptr = Pointer<Utf8>.allocate(count: units.length + 1);
    for (var i = 0; i < units.length; i++) {
      ptr.elementAt(i).load<Utf8>().char = units[i];
    }
    // Add the C string null terminator '\0'
    ptr.elementAt(units.length).load<Utf8>().char = 0;
    return ptr;
  }
}

class DocumentKey extends Struct<DocumentKey> {
  Pointer<Utf8> common_point;

  Pointer<Utf8> encrypted_point;

  Pointer<Utf8> encrypted_key;

  factory DocumentKey.allocate(
          Pointer<Utf8> common_point, Pointer<Utf8> encrypted_point, Pointer<Utf8> encrypted_key) =>
      Pointer<DocumentKey>.allocate().load<DocumentKey>()
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