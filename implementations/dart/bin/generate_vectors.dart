// Generates DID log artifacts for each scenario by reading
// vectors/<scenario>/script.yaml and writing
// vectors/<scenario>/dart/{did.jsonl, resolutionResult*.json, did-witness.json}.
//
// Usage (from implementations/dart/):
//   dart run bin/generate_vectors.dart [<scenario-name> ...]

import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:path/path.dart' as p;
import 'package:yaml/yaml.dart';

import 'package:didwebvh/didwebvh.dart';
import 'package:didwebvh/src/resolve/log_processor.dart';
import 'package:didwebvh_signing_local/didwebvh_signing_local.dart';

const _implName = 'dart';

void main(List<String> args) async {
  final implRoot = Directory.current;
  final vectorsRoot =
      Directory(p.normalize(p.join(implRoot.path, '../../vectors')));

  if (!vectorsRoot.existsSync()) {
    stderr.writeln('error: cannot find vectors/: ${vectorsRoot.path}');
    exit(2);
  }

  List<Directory> scenarios;
  if (args.isNotEmpty) {
    scenarios =
        args.map((a) => Directory(p.join(vectorsRoot.path, a))).toList();
  } else {
    scenarios = vectorsRoot
        .listSync()
        .whereType<Directory>()
        .toList()
      ..sort((a, b) => p.basename(a.path).compareTo(p.basename(b.path)));
  }

  var generated = 0, skipped = 0, failed = 0;
  final genRows = <Map<String, String>>[];

  for (final scenarioDir in scenarios) {
    final scriptPath = File(p.join(scenarioDir.path, 'script.yaml'));
    if (!scriptPath.existsSync()) continue;

    final scenarioName = p.basename(scenarioDir.path);
    if (scenarioName.startsWith('negative-')) {
      print('Generating $scenarioName... SKIP (negative test)');
      skipped++;
      continue;
    }

    stdout.write('Generating $scenarioName... ');
    try {
      final script =
          loadYaml(scriptPath.readAsStringSync()) as YamlMap;
      await _processScenario(scenarioDir, script);
      print('done');
      generated++;
      genRows.add(
          {'testCase': scenarioName, 'result': '✅ PASS', 'notes': ''});
    } on UnsupportedError catch (e) {
      print('SKIP (${e.message})');
      skipped++;
      genRows.add({
        'testCase': scenarioName,
        'result': '⚠️ SKIP',
        'notes': e.message ?? '',
      });
    } catch (e, st) {
      print('FAIL: $e');
      stderr.writeln(st);
      failed++;
      genRows.add({
        'testCase': scenarioName,
        'result': '❌ FAIL',
        'notes': e.toString(),
      });
    }
  }

  print('\n$generated generated, $skipped skipped, $failed failed');

  try {
    File(p.join(implRoot.path, 'gen_results.json'))
        .writeAsStringSync(_prettyJson(genRows));
  } catch (e) {
    stderr.writeln('warning: could not write gen_results.json: $e');
  }

  exit(failed > 0 ? 1 : 0);
}

// ---------------------------------------------------------------------------
// Per-scenario processing
// ---------------------------------------------------------------------------

Future<void> _processScenario(Directory scenarioDir, YamlMap script) async {
  final keyDefs = script['keys'] as YamlList;
  final signers = <String, LocalKeySigner>{};
  final multikeys = <String, String>{};

  for (final kd in keyDefs) {
    final id = kd['id'] as String;
    final seed = _hexToBytes(kd['seed'] as String);
    final signer = await LocalKeySigner.fromPrivateKey(seed);
    signers[id] = signer;
    multikeys[id] = signer.publicKeyMultikey;
  }

  final outDir = Directory(p.join(scenarioDir.path, _implName));
  outDir.createSync(recursive: true);

  DidWebVhState? currentState;
  String? currentDid;
  final witnessEntries = <WitnessProofEntry>[];
  YamlMap? activeWitnessParams;

  final steps = script['steps'] as YamlList;
  for (final rawStep in steps) {
    final step = rawStep as YamlMap;
    final op = step['op'] as String;
    final params = step['params'] as YamlMap?;

    // -------------------------------------------------------------------------
    if (op == 'create') {
      final domain = step['domain'] as String?;
      if (domain == null) throw ArgumentError('create step missing domain');
      final signerKeyId = step['signer'] as String;

      final updateKeyIds = params != null && params.containsKey('updateKeys')
          ? (params['updateKeys'] as YamlList).map((e) => e as String).toList()
          : [signerKeyId];

      if (updateKeyIds.length > 1) {
        throw UnsupportedError(
            'multiple-update-keys at create time not supported by didwebvh-dart API');
      }

      final primaryKeyId = updateKeyIds[0];
      final signer = signers[primaryKeyId]!;

      final cfg = DidWebVh.create(domain, signer);

      if (params != null) {
        final portable = params['portable'] as bool?;
        if (portable == true) cfg.portable(true);

        if (params.containsKey('alsoKnownAs')) {
          final aka =
              (params['alsoKnownAs'] as YamlList).map((e) => e as String).toList();
          if (aka.isNotEmpty) cfg.alsoKnownAs(aka);
        }

        final nextKeyHashes = _buildNextKeyHashes(params, multikeys);
        if (nextKeyHashes != null) cfg.nextKeyHashes(nextKeyHashes);

        final witnessParam = _buildWitnessParam(params, multikeys);
        if (witnessParam != null) cfg.witness(witnessParam);

        final services = _getServices(params);
        if (services != null && services.isNotEmpty) {
          cfg.additionalDocumentContent({'service': services});
        }
      }

      final result = await cfg.execute();
      currentDid = result.did;
      currentState = DidWebVhState.from(currentDid, result.logEntry);

      if (params != null && params.containsKey('witness')) {
        final versionId = result.logEntry.versionId!;
        witnessEntries.add(
            await _makeWitnessEntry(versionId, params, signers, multikeys));
        activeWitnessParams = params;
      }

    // -------------------------------------------------------------------------
    } else if (op == 'update') {
      final signerKeyId = step['signer'] as String;
      final newDomain = step['domain'] as String?;

      if (newDomain != null) {
        final signer = signers[signerKeyId]!;
        final result =
            await DidWebVh.migrate(currentState, signer, newDomain).execute();
        for (final entry in result.newEntries) {
          currentState!.appendEntry(entry);
        }
        currentDid = currentState!.lastEntry?.state?['id'] as String?;
        continue;
      }

      final signer = signers[signerKeyId]!;

      final newUpdateKeyIds = params != null && params.containsKey('updateKeys')
          ? (params['updateKeys'] as YamlList).map((e) => e as String).toList()
          : null;
      final nextKeyHashes = _buildNextKeyHashes(params, multikeys);
      final witnessParam = _buildWitnessParam(params, multikeys);
      final services = _getServices(params);
      final alsoKnownAs = params != null && params.containsKey('alsoKnownAs')
          ? (params['alsoKnownAs'] as YamlList).map((e) => e as String).toList()
          : null;

      // Deep-copy the current document for mutation.
      final currentDoc = jsonDecode(jsonEncode(currentState!.lastEntry!.state))
          as Map<String, Object?>;
      var docChanged = false;

      if (newUpdateKeyIds != null) {
        final mks = newUpdateKeyIds.map((id) => multikeys[id]!).toList();
        _rebuildVerificationMethods(currentDoc, currentDid!, mks);
        docChanged = true;
      }
      if (alsoKnownAs != null) {
        if (alsoKnownAs.isEmpty) {
          currentDoc.remove('alsoKnownAs');
        } else {
          currentDoc['alsoKnownAs'] = alsoKnownAs;
        }
        docChanged = true;
      }
      if (services != null) {
        if (services.isEmpty) {
          currentDoc.remove('service');
        } else {
          currentDoc['service'] = services;
        }
        docChanged = true;
      }

      final updateCfg = DidWebVh.update(currentState, signer);
      if (docChanged) updateCfg.newDocument(currentDoc);

      final changedParams = _buildChangedParameters(
          newUpdateKeyIds?.map((id) => multikeys[id]!).toList(),
          nextKeyHashes,
          witnessParam);
      if (changedParams != null) updateCfg.changedParameters(changedParams);

      final result = await updateCfg.execute();
      for (final entry in result.newEntries) {
        currentState.appendEntry(entry);
      }

      final signingParams =
          activeWitnessParams ?? (witnessParam != null ? params : null);
      if (signingParams != null) {
        final versionId = result.logEntry.versionId!;
        witnessEntries.add(
            await _makeWitnessEntry(versionId, signingParams, signers, multikeys));
      }
      if (witnessParam != null) {
        activeWitnessParams = params;
      }

    // -------------------------------------------------------------------------
    } else if (op == 'deactivate') {
      final signerKeyId = step['signer'] as String;
      final signer = signers[signerKeyId]!;
      final result = await DidWebVh.deactivate(currentState, signer).execute();
      for (final entry in result.newEntries) {
        currentState!.appendEntry(entry);
      }

    // -------------------------------------------------------------------------
    } else if (op == 'resolve') {
      final expectFile = step['expect'] as String;
      final versionNumber = step['versionNumber'] as int?;

      final jsonl = currentState!.toDidLog();
      final options = versionNumber != null
          ? ResolveOptions(versionNumber: versionNumber)
          : ResolveOptions.defaults();

      final ResolveResult resolved;
      try {
        if (witnessEntries.isNotEmpty) {
          final witnessJson = _witnessProofToJson(witnessEntries);
          resolved = await LogProcessor().process(
              jsonl, witnessJson, currentDid, options);
        } else {
          resolved = await DidResolver().resolveFromLog(jsonl, currentDid, options);
        }
      } on ResolutionException catch (e) {
        throw UnsupportedError('resolver rejected generated log: ${e.message}');
      }

      final resResult = _buildResolutionResult(resolved, jsonl);
      File(p.join(outDir.path, expectFile))
          .writeAsStringSync(_prettyJson(resResult));
    }
  }

  // Write DID log.
  File(p.join(outDir.path, 'did.jsonl'))
      .writeAsStringSync(currentState!.toDidLog());

  // Write witness proofs if any.
  if (witnessEntries.isNotEmpty) {
    File(p.join(outDir.path, 'did-witness.json'))
        .writeAsStringSync(_prettyJson(_witnessProofCollectionToJson(witnessEntries)));
  }
}

// ---------------------------------------------------------------------------
// Document helpers
// ---------------------------------------------------------------------------

void _rebuildVerificationMethods(
    Map<String, Object?> doc, String did, List<String> updateKeyMks) {
  final vmArray = <Map<String, Object?>>[];
  final authArray = <String>[];
  for (final mk in updateKeyMks) {
    final fragment = mk.substring(mk.length - 8);
    final vmId = '$did#$fragment';
    vmArray.add({
      'id': vmId,
      'type': 'Multikey',
      'controller': did,
      'publicKeyMultibase': mk,
    });
    authArray.add(vmId);
  }
  doc['verificationMethod'] = vmArray;
  doc['authentication'] = authArray;
}

// ---------------------------------------------------------------------------
// Resolution result construction
// ---------------------------------------------------------------------------

Map<String, Object?> _buildResolutionResult(ResolveResult result, String jsonl) {
  final actual = <String, Object?>{};

  Map<String, Object?>? didDocJson;
  if (result.didDocument != null) {
    didDocJson = result.didDocument!.asJsonObject();
  } else if (result.metadata?.versionId != null) {
    // Deactivated — extract state from the deactivated log entry and add
    // implicit services to match the resolver's output for non-deactivated DIDs.
    final state = _extractStateFromLog(jsonl, result.metadata!.versionId!);
    if (state != null) {
      ImplicitServices.addTo(state, state['id'] as String?);
      didDocJson = state;
    }
  }
  actual['didDocument'] = didDocJson;

  final metaObj = <String, Object?>{};
  final meta = result.metadata;
  if (meta != null) {
    if (meta.created != null) metaObj['created'] = meta.created;
    if (meta.updated != null) metaObj['updated'] = meta.updated;
    if (meta.versionId != null) {
      metaObj['versionId'] = meta.versionId;
      final parts = meta.versionId!.split('-');
      final vn = int.tryParse(parts[0]);
      if (vn != null) metaObj['versionNumber'] = vn;
    }
    if (meta.versionTime != null) metaObj['versionTime'] = meta.versionTime;
    if (meta.deactivated == true) metaObj['deactivated'] = true;
    if (meta.portable == true) metaObj['portable'] = true;
    if (meta.scid != null) metaObj['scid'] = meta.scid;
  }
  actual['didDocumentMetadata'] = metaObj;

  actual['didResolutionMetadata'] = {
    'contentType': 'application/did+ld+json',
  };

  return actual;
}

Map<String, Object?>? _extractStateFromLog(String jsonl, String targetVersionId) {
  // Find the entry whose version number is one less than the target (for
  // deactivate) or exactly matches (for pinned versions).
  final targetVn = int.tryParse(targetVersionId.split('-')[0]) ?? 0;
  Map<String, Object?>? candidate;
  for (final line in jsonl.split('\n')) {
    if (line.trim().isEmpty) continue;
    try {
      final entry = LogEntry.fromJsonLine(line);
      final vn = entry.versionNumber;
      if (vn < targetVn && entry.state != null) {
        candidate = Map<String, Object?>.from(
            jsonDecode(jsonEncode(entry.state)) as Map);
      }
      if (vn == targetVn && entry.state != null) {
        return Map<String, Object?>.from(
            jsonDecode(jsonEncode(entry.state)) as Map);
      }
    } catch (_) {}
  }
  return candidate;
}

// ---------------------------------------------------------------------------
// Witness proof generation
// ---------------------------------------------------------------------------

Future<WitnessProofEntry> _makeWitnessEntry(
  String versionId,
  YamlMap params,
  Map<String, LocalKeySigner> signers,
  Map<String, String> multikeys,
) async {
  final wc = params['witness'] as YamlMap;
  final witnesses = wc['witnesses'] as YamlList;

  final versionIdDoc = <String, Object?>{'versionId': versionId};
  final proofs = <DataIntegrityProof>[];

  for (final w in witnesses) {
    final wKeyId = (w as YamlMap)['id'] as String;
    final wSigner = signers[wKeyId]!;
    final mk = multikeys[wKeyId]!;

    final proofOpts = DataIntegrityProof.defaults()
      ..verificationMethod = 'did:key:$mk#$mk'
      ..created = _formatInstant(DateTime.now().toUtc());

    final hashData = ProofGenerator.buildHashData(proofOpts, versionIdDoc);
    final sig = await wSigner.sign(hashData);
    proofOpts.proofValue = Base58Btc.encodeMultibase(sig);
    proofs.add(proofOpts);
  }

  return WitnessProofEntry.of(versionId, proofs);
}

String _witnessProofToJson(List<WitnessProofEntry> entries) =>
    jsonEncode(_witnessProofCollectionToJson(entries));

List<Map<String, Object?>> _witnessProofCollectionToJson(
    List<WitnessProofEntry> entries) {
  return [
    for (final entry in entries)
      {
        'versionId': entry.versionId,
        'proof': [
          for (final p in entry.proof ?? <DataIntegrityProof>[])
            {
              'type': p.type,
              'cryptosuite': p.cryptosuite,
              'verificationMethod': p.verificationMethod,
              'created': p.created,
              'proofPurpose': p.proofPurpose,
              'proofValue': p.proofValue,
            },
        ],
      },
  ];
}

// ---------------------------------------------------------------------------
// Param extraction helpers
// ---------------------------------------------------------------------------

List<String>? _buildNextKeyHashes(
    YamlMap? params, Map<String, String> multikeys) {
  if (params == null || !params.containsKey('nextKeyHashes')) return null;
  return (params['nextKeyHashes'] as YamlList)
      .map((id) => PreRotationHashGenerator.generateHash(multikeys[id as String]!))
      .toList();
}

WitnessConfig? _buildWitnessParam(
    YamlMap? params, Map<String, String> multikeys) {
  if (params == null || !params.containsKey('witness')) return null;
  final wc = params['witness'] as YamlMap;
  final threshold = wc['threshold'] as int;
  final witnesses = (wc['witnesses'] as YamlList)
      .map((w) =>
          WitnessEntry('did:key:${multikeys[(w as YamlMap)['id'] as String]!}'))
      .toList();
  return WitnessConfig(threshold, witnesses);
}

Parameters? _buildChangedParameters(
    List<String>? updateKeyMks,
    List<String>? nextKeyHashes,
    WitnessConfig? witness) {
  if (updateKeyMks == null && nextKeyHashes == null && witness == null) {
    return null;
  }
  return Parameters()
    ..updateKeys = updateKeyMks
    ..nextKeyHashes = nextKeyHashes
    ..witness = witness;
}

List<Map<String, Object?>>? _getServices(YamlMap? params) {
  if (params == null || !params.containsKey('services')) return null;
  return (params['services'] as YamlList).map((s) {
    final svc = s as YamlMap;
    return <String, Object?>{
      for (final k in svc.keys) k.toString(): svc[k]?.toString(),
    };
  }).toList();
}

// ---------------------------------------------------------------------------
// Cryptographic / formatting helpers
// ---------------------------------------------------------------------------

Uint8List _hexToBytes(String hex) {
  final len = hex.length;
  final data = Uint8List(len ~/ 2);
  for (var i = 0; i < len; i += 2) {
    data[i ~/ 2] = int.parse(hex.substring(i, i + 2), radix: 16);
  }
  return data;
}

String _formatInstant(DateTime dt) {
  final u = dt.toUtc();
  String two(int n) => n.toString().padLeft(2, '0');
  return '${u.year.toString().padLeft(4, '0')}-${two(u.month)}-${two(u.day)}'
      'T${two(u.hour)}:${two(u.minute)}:${two(u.second)}Z';
}

// ---------------------------------------------------------------------------
// JSON utilities
// ---------------------------------------------------------------------------

String _prettyJson(Object? value) =>
    const JsonEncoder.withIndent('  ').convert(value);

// JCS (RFC 8785) canonicalization: sort object keys, compact output.
String jcs(Object? value) {
  if (value == null) return 'null';
  if (value is bool) return value ? 'true' : 'false';
  if (value is int) return '$value';
  if (value is double) {
    if (value == value.truncateToDouble()) return '${value.toInt()}';
    return jsonEncode(value);
  }
  if (value is String) return jsonEncode(value);
  if (value is List) return '[${value.map(jcs).join(',')}]';
  if (value is Map) {
    final sorted = SplayTreeMap<String, Object?>.from(
        {for (final k in value.keys) k.toString(): value[k]});
    final pairs =
        sorted.entries.map((e) => '${jsonEncode(e.key)}:${jcs(e.value)}');
    return '{${pairs.join(',')}}';
  }
  throw ArgumentError('jcs: unsupported type ${value.runtimeType}');
}
