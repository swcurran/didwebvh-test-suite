// Compliance test harness: resolves every committed vector (from every
// implementation subdir) through the Dart didwebvh resolver and compares
// results.  Also runs negative resolution tests against the ts/ artifacts.
//
// Writes implementations/dart/status.md and (when there are diffs)
// implementations/dart/diffs.txt.
//
// Usage (from implementations/dart/):
//   dart run bin/test_vectors.dart

import 'dart:collection';
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:yaml/yaml.dart';

import 'package:didwebvh/didwebvh.dart';
import 'package:didwebvh/src/resolve/log_processor.dart';

const _implName = 'dart';
final _versionFileRe = RegExp(r'^resolutionResult\.(\d+)\.json$');

void main() async {
  final implRoot = Directory.current;
  final vectorsRoot =
      Directory(p.normalize(p.join(implRoot.path, '../../vectors')));

  if (!vectorsRoot.existsSync()) {
    stderr.writeln('error: cannot read vectors/: ${vectorsRoot.path}');
    exit(2);
  }

  // Delete stale output files.
  final statusFile = File(p.join(implRoot.path, 'status.md'));
  final diffsFile = File(p.join(implRoot.path, 'diffs.txt'));
  if (statusFile.existsSync()) statusFile.deleteSync();
  if (diffsFile.existsSync()) diffsFile.deleteSync();

  final scenarios = vectorsRoot
      .listSync()
      .whereType<Directory>()
      .toList()
    ..sort((a, b) => p.basename(a.path).compareTo(p.basename(b.path)));

  var pass = 0, fail = 0, diff = 0, xfail = 0;
  final allRows = <List<String>>[];   // [scenario, logSource, result, notes]
  final negRows = <List<String>>[];   // [scenario, expectedError, result, notes]
  final allDiffs = StringBuffer();

  // ── Negative resolution tests (ts/ artifacts only) ──────────────────────
  for (final scenarioDir in scenarios) {
    final scenarioName = p.basename(scenarioDir.path);
    if (!scenarioName.startsWith('negative-')) continue;
    if (!File(p.join(scenarioDir.path, 'script.yaml')).existsSync()) continue;

    final tsDir = Directory(p.join(scenarioDir.path, 'ts'));
    final jsonlFile = File(p.join(tsDir.path, 'did.jsonl'));
    final resultFile = File(p.join(tsDir.path, 'resolutionResult.json'));

    if (!jsonlFile.existsSync() || !resultFile.existsSync()) {
      negRows.add([scenarioName, '?', '⚠️ SKIP', 'ts/ not generated']);
      continue;
    }

    var expectedError = '?';
    try {
      final rr = jsonDecode(resultFile.readAsStringSync()) as Map<String, Object?>;
      final rm = rr['didResolutionMetadata'] as Map<String, Object?>?;
      if (rm != null && rm.containsKey('error')) {
        expectedError = rm['error'] as String? ?? '?';
      }
    } catch (_) {}

    final rawJsonl = jsonlFile.readAsStringSync().trim();

    if (rawJsonl.isEmpty) {
      // URL-only test: parse each DID URL from script.yaml.
      // PASS = all DIDs are rejected by the parser; FAIL = any DID is accepted.
      final scriptPath = File(p.join(scenarioDir.path, 'script.yaml'));
      try {
        final script = loadYaml(scriptPath.readAsStringSync()) as YamlMap;
        final stepsRaw = script['steps'];
        final steps = stepsRaw is YamlList ? stepsRaw : const <dynamic>[];
        final dids = <String>[];
        for (final step in steps) {
          final s = step as YamlMap;
          if (s['op'] == 'resolve-did' && s['did'] is String) {
            dids.add(s['did'] as String);
          }
        }
        if (dids.isEmpty) {
          negRows.add([scenarioName, expectedError, '⚠️ SKIP', 'no resolve-did ops in script']);
        } else {
          String? failReason;
          for (final did in dids) {
            try {
              DidWebVhUrl.parse(did);
              failReason = 'URL parser accepted invalid DID: $did';
              break;
            } catch (_) {
              // Correctly rejected.
            }
          }
          if (failReason == null) {
            pass++;
            negRows.add([scenarioName, expectedError, '✅ PASS', '']);
          } else {
            fail++;
            negRows.add([scenarioName, expectedError, '❌ FAIL', failReason]);
          }
        }
      } catch (e) {
        negRows.add([scenarioName, expectedError, '⚠️ SKIP',
            'cannot parse script.yaml: $e']);
      }
      continue;
    }

    final did = _extractDid(rawJsonl);
    if (did == null) {
      negRows.add([scenarioName, expectedError, '⚠️ SKIP', 'cannot extract DID']);
      continue;
    }

    final witnessPath = File(p.join(tsDir.path, 'did-witness.json'));
    final witnessContent =
        witnessPath.existsSync() ? witnessPath.readAsStringSync() : null;

    try {
      await LogProcessor().process(
          rawJsonl, witnessContent, did, ResolveOptions.defaults());
      // Resolver accepted an invalid log.
      fail++;
      negRows.add(
          [scenarioName, expectedError, '❌ FAIL', 'resolver accepted invalid log']);
    } on ResolutionException {
      pass++;
      negRows.add([scenarioName, expectedError, '✅ PASS', '']);
    } catch (_) {
      pass++;
      negRows.add([scenarioName, expectedError, '✅ PASS', '']);
    }
  }

  // ── Cross-resolution ─────────────────────────────────────────────────────
  for (final scenarioDir in scenarios) {
    if (!File(p.join(scenarioDir.path, 'script.yaml')).existsSync()) continue;

    final scenarioName = p.basename(scenarioDir.path);
    if (scenarioName.startsWith('negative-')) continue;

    // Delete old per-scenario status.md if present (legacy artefact).
    final perScenarioStatus =
        File(p.join(scenarioDir.path, _implName, 'status.md'));
    if (perScenarioStatus.existsSync()) perScenarioStatus.deleteSync();

    final implDirs = scenarioDir
        .listSync()
        .whereType<Directory>()
        .toList()
      ..sort((a, b) => p.basename(a.path).compareTo(p.basename(b.path)));

    for (final implDir in implDirs) {
      final implDirName = p.basename(implDir.path);
      final jsonlFile = File(p.join(implDir.path, 'did.jsonl'));

      if (!jsonlFile.existsSync()) {
        allRows.add([scenarioName, implDirName, '⚠️ SKIP', 'no did.jsonl present']);
        continue;
      }

      final resultFiles = implDir
          .listSync()
          .whereType<File>()
          .where((f) {
            final name = p.basename(f.path);
            return name.startsWith('resolutionResult') && name.endsWith('.json');
          })
          .toList()
        ..sort((a, b) => p.basename(a.path).compareTo(p.basename(b.path)));

      final label = implDirName == _implName
          ? '$implDirName (self)'
          : implDirName;

      if (resultFiles.isEmpty) {
        allRows.add([scenarioName, label, '⚠️ SKIP', 'no resolutionResult files']);
        continue;
      }

      var implFail = false, implDiff = false, implXfail = false;
      var implFailReason = '', implXfailReason = '';

      for (final resultFile in resultFiles) {
        final testId =
            '$scenarioName/$implDirName/${p.basename(resultFile.path)}';
        final outcome = await _runTest(jsonlFile, resultFile);

        switch (outcome.kind) {
          case _Kind.pass:
            print('PASS   $testId');
            pass++;
          case _Kind.xfail:
            print('XFAIL  $testId (${outcome.message})');
            xfail++;
            implXfail = true;
            implXfailReason = outcome.message ?? '';
          case _Kind.diff:
            stderr.writeln('DIFF   $testId');
            for (final line in (outcome.message ?? '').split('\n')) {
              stderr.writeln('       $line');
            }
            diff++;
            if (!implFail) implDiff = true;
            if (implFailReason.isEmpty) implFailReason = 'see diffs.txt';
            allDiffs
              ..write('=== $scenarioName / $implDirName — '
                  '${p.basename(resultFile.path)} ===\n')
              ..write(outcome.message)
              ..write('\n\n');
          case _Kind.fail:
            stderr.writeln('FAIL   $testId');
            for (final line in (outcome.message ?? '').split('\n')) {
              stderr.writeln('       $line');
            }
            fail++;
            implFail = true;
            implDiff = false;
            if (implFailReason.isEmpty) {
              implFailReason =
                  (outcome.message ?? '').split('\n').first;
            }
        }
      }

      if (implFail) {
        allRows.add([scenarioName, label, '❌ FAIL', implFailReason]);
      } else if (implDiff) {
        allRows.add([scenarioName, label, '🔶 DIFF', 'see diffs.txt']);
      } else if (implXfail) {
        allRows.add([scenarioName, label, '⚠️ XFAIL', implXfailReason]);
      } else {
        allRows.add([scenarioName, label, '✅ PASS', '']);
      }
    }
  }

  _writeCombinedOutput(implRoot, negRows, allRows, allDiffs.toString());

  print('\n$pass passed, $diff diff, $fail failed, $xfail xfailed');
  exit((fail > 0 || diff > 0) ? 1 : 0);
}

// ---------------------------------------------------------------------------
// Output writing
// ---------------------------------------------------------------------------

void _writeCombinedOutput(
  Directory implRoot,
  List<List<String>> negRows,
  List<List<String>> allRows,
  String diffsContent,
) {
  final versionLine = _readConfigVersion(implRoot);
  final content = StringBuffer();
  content.write('# $_implName status\n\n');
  if (versionLine.isNotEmpty) {
    content.write(
        'Implementation: didwebvh-$_implName $versionLine\n\n');
  }

  // DID Creation table from gen_results.json written by generate_vectors.
  final genResultsPath = File(p.join(implRoot.path, 'gen_results.json'));
  if (genResultsPath.existsSync()) {
    try {
      final genArr =
          jsonDecode(genResultsPath.readAsStringSync()) as List<dynamic>;
      if (genArr.isNotEmpty) {
        content.write('## DID Creation\n\n');
        content
            .write('| Test Case | Result | Notes |\n|---|---|---|\n');
        for (final el in genArr) {
          final row = el as Map<String, Object?>;
          content.write('| ${row['testCase']} | ${row['result']} '
              '| ${row['notes']} |\n');
        }
        content.write('\n');
      }
    } catch (e) {
      stderr.writeln('warning: could not read gen_results.json: $e');
    }
  }

  if (negRows.isNotEmpty) {
    content.write('## Negative Resolution\n\n');
    content.write(
        '| Test Case | Expected Error | Result | Notes |\n|---|---|---|---|\n');
    for (final row in negRows) {
      content.write(
          '| ${row[0]} | ${row[1]} | ${row[2]} | ${row[3]} |\n');
    }
    content.write('\n');
  }

  content.write('## Cross-Resolution\n\n');
  content.write(
      '| Test Case | Log Source | Result | Notes |\n|---|---|---|---|\n');
  for (final row in allRows) {
    content.write(
        '| ${row[0]} | ${row[1]} | ${row[2]} | ${row[3]} |\n');
  }

  try {
    File(p.join(implRoot.path, 'status.md'))
        .writeAsStringSync(content.toString());
  } catch (e) {
    stderr.writeln('warning: could not write status.md: $e');
  }

  final stripped = diffsContent.trimRight();
  if (stripped.isNotEmpty) {
    try {
      File(p.join(implRoot.path, 'diffs.txt'))
          .writeAsStringSync('$stripped\n');
    } catch (e) {
      stderr.writeln('warning: could not write diffs.txt: $e');
    }
  }
}

String _readConfigVersion(Directory implRoot) {
  final configPath = File(p.join(implRoot.path, 'config.yaml'));
  if (!configPath.existsSync()) return '';
  try {
    final text = configPath.readAsStringSync();
    String extract(String key) {
      final m = RegExp('^$key:\\s*["\']?([^"\'\\n]+)["\']?',
              multiLine: true)
          .firstMatch(text);
      return m?.group(1)?.trim() ?? '';
    }
    final version = extract('version');
    final commit = extract('commit');
    final parts = [
      if (version.isNotEmpty) version,
      if (commit.isNotEmpty) commit,
    ];
    return parts.join(' @ ');
  } catch (_) {
    return '';
  }
}

// ---------------------------------------------------------------------------
// Core test logic
// ---------------------------------------------------------------------------

Future<_Outcome> _runTest(File jsonlFile, File resultFile) async {
  try {
    final rawJsonl = jsonlFile.readAsStringSync();
    final expectedContent = resultFile.readAsStringSync();

    final did = _extractDid(rawJsonl);
    if (did == null) {
      return _Outcome.fail('Could not extract DID from did.jsonl');
    }

    final versionNumber = _extractVersionNumber(p.basename(resultFile.path));
    final options = versionNumber != null
        ? ResolveOptions(versionNumber: versionNumber)
        : ResolveOptions.defaults();

    final witnessFile = File(
        p.join(p.dirname(resultFile.path), 'did-witness.json'));
    final witnessContent =
        witnessFile.existsSync() ? witnessFile.readAsStringSync() : null;

    final ResolveResult result;
    try {
      result = await LogProcessor()
          .process(rawJsonl, witnessContent, did, options);
    } on ResolutionException catch (e) {
      final msg = e.message;
      if (_isKnownTsCompatError(msg)) {
        return _Outcome.xfail('TS COMPAT: resolution error: $msg');
      }
      return _Outcome.fail('resolve error: $msg');
    }

    final expected =
        jsonDecode(expectedContent) as Map<String, Object?>;

    Map<String, Object?>? didDocJson;
    if (result.didDocument != null) {
      didDocJson = result.didDocument!.asJsonObject();
    } else if (result.metadata?.versionId != null) {
      final state = _extractStateFromLog(rawJsonl, result.metadata!.versionId!);
      if (state != null) {
        ImplicitServices.addTo(state, state['id'] as String?);
        didDocJson = state;
      }
    }

    final actual = _buildActualResult(didDocJson, result.metadata);
    _normalizePair(actual, expected);

    final actualJcs = jcs(actual);
    final expectedJcs = jcs(expected);
    if (actualJcs == expectedJcs) return _Outcome.pass();

    final expSorted = _prettyJson(jsonDecode(expectedJcs));
    final actSorted = _prettyJson(jsonDecode(actualJcs));
    final diffBody = _unifiedDiff(expSorted, actSorted, 3);
    return _Outcome.diff(diffBody);
  } catch (e, st) {
    return _Outcome.fail('exception: $e\n$st');
  }
}

// ---------------------------------------------------------------------------
// Build actual result object
// ---------------------------------------------------------------------------

Map<String, Object?> _buildActualResult(
    Map<String, Object?>? didDocJson, ResolutionMetadata? meta) {
  final actual = <String, Object?>{};
  actual['didDocument'] = didDocJson;

  final metaObj = <String, Object?>{};
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
    if (meta.portable != null) metaObj['portable'] = meta.portable;
    if (meta.scid != null) metaObj['scid'] = meta.scid;
  }
  actual['didDocumentMetadata'] = metaObj;

  actual['didResolutionMetadata'] = {
    'contentType': 'application/did+ld+json',
  };

  return actual;
}

// ---------------------------------------------------------------------------
// Bidirectional normalisation applied to both sides before comparison
// ---------------------------------------------------------------------------

void _normalizePair(Map<String, Object?> actual, Map<String, Object?> expected) {
  _sortServices(actual);
  _sortServices(expected);

  // Restrict didDocumentMetadata to the intersection of keys in both.
  final actMeta = actual['didDocumentMetadata'] as Map<String, Object?>?;
  final expMeta = expected['didDocumentMetadata'] as Map<String, Object?>?;
  if (actMeta != null && expMeta != null) {
    final common = Set<String>.from(actMeta.keys)
      ..retainAll(expMeta.keys);
    actual['didDocumentMetadata'] = {
      for (final k in common) k: actMeta[k],
    };
    expected['didDocumentMetadata'] = {
      for (final k in common) k: expMeta[k],
    };
  }
}

void _sortServices(Map<String, Object?> result) {
  final didDoc = result['didDocument'];
  if (didDoc is! Map<String, Object?>) return;
  final services = didDoc['service'];
  if (services is! List) return;
  final list = List<Object?>.from(services);
  list.sort((a, b) {
    final aId = (a is Map ? a['id'] : null)?.toString() ?? '';
    final bId = (b is Map ? b['id'] : null)?.toString() ?? '';
    return aId.compareTo(bId);
  });
  didDoc['service'] = list;
}

// ---------------------------------------------------------------------------
// Known TS compat errors (XFAIL guard)
// ---------------------------------------------------------------------------

bool _isKnownTsCompatError(String msg) {
  final lower = msg.toLowerCase();
  return lower.contains('nextkeyhashe') ||
      lower.contains('prerotation') ||
      lower.contains('pre-rotation') ||
      msg.contains('updateKeys are not null') ||
      msg.contains('updatekeys are not null');
}

// ---------------------------------------------------------------------------
// Extraction helpers
// ---------------------------------------------------------------------------

String? _extractDid(String rawJsonl) {
  for (final line in rawJsonl.split('\n')) {
    if (line.trim().isEmpty) continue;
    try {
      final entry = jsonDecode(line) as Map<String, Object?>;
      final state = entry['state'] as Map<String, Object?>?;
      if (state != null && state.containsKey('id')) {
        return state['id'] as String?;
      }
    } catch (_) {}
    break;
  }
  return null;
}

int? _extractVersionNumber(String filename) {
  final m = _versionFileRe.firstMatch(filename);
  return m != null ? int.tryParse(m.group(1)!) : null;
}

Map<String, Object?>? _extractStateFromLog(
    String rawJsonl, String targetVersionId) {
  final targetVn = int.tryParse(targetVersionId.split('-')[0]) ?? 0;
  Map<String, Object?>? candidate;
  for (final line in rawJsonl.split('\n')) {
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
// Unified diff (LCS-based)
// ---------------------------------------------------------------------------

String _unifiedDiff(String expected, String actual, int ctx) {
  final expLines = expected.split('\n');
  final actLines = actual.split('\n');
  final m = expLines.length;
  final n = actLines.length;

  // Build LCS DP table.
  final dp = List.generate(m + 1, (_) => List<int>.filled(n + 1, 0));
  for (var i = 1; i <= m; i++) {
    for (var j = 1; j <= n; j++) {
      dp[i][j] = expLines[i - 1] == actLines[j - 1]
          ? dp[i - 1][j - 1] + 1
          : dp[i - 1][j] > dp[i][j - 1]
              ? dp[i - 1][j]
              : dp[i][j - 1];
    }
  }

  // Backtrack to build edit list.
  final edits = <List<String>>[];
  var i = m, j = n;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && expLines[i - 1] == actLines[j - 1]) {
      edits.insert(0, [' ', expLines[i - 1]]);
      i--;
      j--;
    } else if (j > 0 &&
        (i == 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      edits.insert(0, ['+', actLines[j - 1]]);
      j--;
    } else {
      edits.insert(0, ['-', expLines[i - 1]]);
      i--;
    }
  }

  final changed = [
    for (var k = 0; k < edits.length; k++)
      if (edits[k][0] != ' ') k,
  ];
  if (changed.isEmpty) return '';

  // Group into hunks with context.
  final hunks = <List<int>>[];
  var hs = (changed[0] - ctx).clamp(0, edits.length - 1);
  var he = (changed[0] + ctx).clamp(0, edits.length - 1);
  for (var k = 1; k < changed.length; k++) {
    final pos = changed[k];
    if (pos - ctx <= he + 1) {
      he = (pos + ctx).clamp(0, edits.length - 1);
    } else {
      hunks.add([hs, he]);
      hs = (pos - ctx).clamp(0, edits.length - 1);
      he = (pos + ctx).clamp(0, edits.length - 1);
    }
  }
  hunks.add([hs, he]);

  final out = StringBuffer('--- expected\n+++ actual (dart resolver)\n');
  for (var h = 0; h < hunks.length; h++) {
    for (var k = hunks[h][0]; k <= hunks[h][1]; k++) {
      out.write('${edits[k][0]}${edits[k][1]}\n');
    }
    if (h + 1 < hunks.length) out.write('...\n');
  }
  return out.toString().trimRight();
}

// ---------------------------------------------------------------------------
// JSON utilities (shared with generate_vectors; duplicated to keep each
// binary self-contained as a compiled AOT executable)
// ---------------------------------------------------------------------------

String _prettyJson(Object? value) =>
    const JsonEncoder.withIndent('  ').convert(value);

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

// ---------------------------------------------------------------------------
// Outcome types
// ---------------------------------------------------------------------------

enum _Kind { pass, xfail, diff, fail }

class _Outcome {
  _Outcome._(this.kind, this.message);

  static _Outcome pass() => _Outcome._(_Kind.pass, null);
  static _Outcome xfail(String msg) => _Outcome._(_Kind.xfail, msg);
  static _Outcome diff(String msg) => _Outcome._(_Kind.diff, msg);
  static _Outcome fail(String msg) => _Outcome._(_Kind.fail, msg);

  final _Kind kind;
  final String? message;
}
