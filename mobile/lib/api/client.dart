/// The TrueMed REST client: all eleven endpoints of DATA-CONTRACT.md §4.3.
///
/// # What this layer is responsible for
///
/// Turning network reality into either a typed model or a [TrueMedException] whose
/// `code` the UI can switch on. Nothing above this file should ever see a
/// `SocketException`, an HTTP status, or a JSON map.
///
/// # Three decisions worth explaining
///
/// **Public endpoints never send an API key.** Not "usually" — never, structurally,
/// because the key is only attached inside [_authorised] and the public methods do
/// not call it. `POST /api/report` is the reason. Anonymous counterfeit reporting is
/// a requirement (§4.5, and the DPDP Act's data-minimisation principle), and a
/// pharmacist's key attached to a report would deanonymise the one person in the
/// supply chain who took a risk by filing it. A key on a public endpoint would also
/// be a plain leak: it would appear in the access log of every proxy on the path.
///
/// **Redirects are not followed.** `followRedirects = false`, and a 3xx is reported
/// as a configuration error naming the `Location`. The alternative is worse than it
/// looks: a deployment whose HTTPS origin 301s to HTTP, or a captive portal that
/// redirects everything to itself, would otherwise have the app resend the request —
/// with its `X-API-Key` header — to wherever it was pointed, over whatever transport
/// it was given. Refusing costs one clear error message at setup time.
///
/// **A failure to reach the API is never a statement about the medicine.** Transport
/// failures map to [Codes.networkUnavailable] and 502/503/504 to
/// [Codes.upstreamUnavailable], both of which `isTransportFailure` reports true for,
/// so `withNetworkFailure` in the core degrades the scan to its offline result
/// instead of showing an error. An unexpected *bug* in this file maps to
/// [Codes.internalError] rather than to a transport code, so that a defect here
/// cannot disguise itself as poor signal and leave the app permanently offline with
/// nobody the wiser.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io' show IOException, SocketException, TlsException;

import 'package:http/http.dart' as http;

import '../config.dart';
import '../core/errors.dart';
import '../core/payload.dart';
import '../core/rules.dart';
import 'envelope.dart';
import 'models.dart';

/// Supplies the stored API key, or null when the user has not signed in.
///
/// A callback rather than a string so the client never holds a copy of the key
/// alive in memory between calls, and so a key revoked mid-session is picked up on
/// the next request without rebuilding the client.
typedef ApiKeyProvider = Future<String?> Function();

/// Sent so API access logs can attribute traffic and spot an outdated build.
const String userAgent = 'TrueMed/1.0.0 (Flutter)';

class TrueMedApi {
  TrueMedApi({
    String? baseUrl,
    http.Client? httpClient,
    ApiKeyProvider? apiKeyProvider,
    Duration? timeout,
  })  : baseUri = _parseBase(baseUrl ?? apiBaseUrl),
        _client = httpClient ?? http.Client(),
        _apiKeyProvider = apiKeyProvider,
        _timeout = timeout ?? apiTimeout,
        _ownsClient = httpClient == null;

  final Uri baseUri;
  final http.Client _client;
  final ApiKeyProvider? _apiKeyProvider;
  final Duration _timeout;
  final bool _ownsClient;

  /// Validate `TRUEMED_API_BASE` once, at construction, with a message that says
  /// what to do about it.
  ///
  /// Left to `Uri.parse` this would fail much later and much less clearly: a base of
  /// `192.168.1.7:3000` parses successfully as a URI with scheme `192.168.1.7`, and
  /// the first request then fails deep inside `http` with "unsupported scheme".
  static Uri _parseBase(String raw) {
    final String trimmed = raw.trim();
    if (trimmed.isEmpty) {
      throw TrueMedException(
        Codes.internalError,
        'TRUEMED_API_BASE is empty. Build with '
        '--dart-define=TRUEMED_API_BASE=https://api.example.com',
      );
    }
    // Strip trailing slashes so path joining cannot produce `//api/verify`, which
    // some routers treat as a different path.
    String cleaned = trimmed;
    while (cleaned.endsWith('/')) {
      cleaned = cleaned.substring(0, cleaned.length - 1);
    }
    final Uri parsed = Uri.parse(cleaned);
    if (parsed.scheme != 'http' && parsed.scheme != 'https') {
      throw TrueMedException(
        Codes.internalError,
        'TRUEMED_API_BASE must start with http:// or https:// (got "$raw"). '
        'A bare host:port parses as a URI whose scheme is the hostname, which '
        'fails much later and much less clearly.',
      );
    }
    if (parsed.host.isEmpty) {
      throw TrueMedException(
        Codes.internalError,
        'TRUEMED_API_BASE has no host (got "$raw")',
      );
    }
    if (parsed.hasQuery || parsed.hasFragment) {
      throw TrueMedException(
        Codes.internalError,
        'TRUEMED_API_BASE must not carry a query string or fragment (got "$raw")',
      );
    }
    return parsed;
  }

  Uri _uri(String path, [Map<String, String>? query]) {
    final String base = baseUri.path.endsWith('/')
        ? baseUri.path.substring(0, baseUri.path.length - 1)
        : baseUri.path;
    return baseUri.replace(
      path: '$base$path',
      queryParameters: query == null || query.isEmpty ? null : query,
    );
  }

  /// Fetch the API key, refusing to proceed without a well-formed one.
  ///
  /// The format check is local and saves a round trip, but the reason it is here
  /// rather than in the UI is that it is the last point before the key leaves the
  /// device: a value that is not `tm_{role}_{32 hex}` is not a key, and sending it
  /// would put a user's mistyped password into a server access log.
  Future<String> _authorised(String what) async {
    final ApiKeyProvider? provider = _apiKeyProvider;
    if (provider == null) {
      throw TrueMedException(
        Codes.unauthorized,
        '$what needs an API key, but this client was built without a key '
        'provider',
      );
    }
    final String? key = await provider();
    if (key == null || key.isEmpty) {
      throw TrueMedException(
        Codes.unauthorized,
        '$what needs you to sign in first',
      );
    }
    final String trimmed = key.trim();
    if (!apiKeyRe.hasMatch(trimmed)) {
      throw TrueMedException(
        Codes.unauthorized,
        'the stored API key is not in the form tm_{role}_{32 hex characters}, '
        'so it has not been sent. Sign in again with the key CDSCO issued.',
      );
    }
    return trimmed;
  }

  // ── Transport ──────────────────────────────────────────────────────────────

  Future<ApiResult> _get(
    String path, {
    Map<String, String>? query,
    String? apiKey,
    Duration? timeout,
    required String what,
  }) =>
      _perform(
        http.Request('GET', _uri(path, query)),
        apiKey: apiKey,
        timeout: timeout,
        what: what,
      );

  Future<ApiResult> _post(
    String path,
    Map<String, Object?> body, {
    String? apiKey,
    Duration? timeout,
    required String what,
  }) {
    final http.Request request = http.Request('POST', _uri(path));
    request.headers['content-type'] = 'application/json; charset=utf-8';
    // `bodyBytes` rather than `body` so the encoding is explicit UTF-8 and not
    // whatever the package infers from a content-type header we set ourselves.
    request.bodyBytes = utf8.encode(jsonEncode(body));
    return _perform(request, apiKey: apiKey, timeout: timeout, what: what);
  }

  Future<ApiResult> _perform(
    http.Request request, {
    String? apiKey,
    Duration? timeout,
    required String what,
  }) async {
    request.headers['accept'] = 'application/json';
    request.headers['user-agent'] = userAgent;
    if (apiKey != null) request.headers['x-api-key'] = apiKey;
    // See the library note: a redirect must not be allowed to move this request,
    // and its API key header, to a host or scheme we did not choose.
    request.followRedirects = false;

    final Duration budget = timeout ?? _timeout;
    final DateTime deadline = DateTime.now().add(budget);

    http.StreamedResponse streamed;
    try {
      streamed = await _client.send(request).timeout(budget);
    } on TimeoutException {
      throw networkUnavailable(
        '$what timed out after ${budget.inSeconds}s while connecting',
      );
    } on TlsException catch (err) {
      // Reported separately from a plain socket failure because the two need
      // different fixes and look identical in a bug report otherwise: this one is
      // an expired certificate or an intercepting proxy, not poor signal.
      throw networkUnavailable(
        '$what could not establish a secure connection (${err.message}). The '
        "server's certificate may be expired, or something on this network is "
        'intercepting traffic.',
      );
    } on SocketException catch (err) {
      throw networkUnavailable(
        '$what could not reach ${baseUri.host} (${err.message})',
      );
    } on http.ClientException catch (err) {
      throw networkUnavailable('$what failed: ${err.message}');
    } on IOException catch (err) {
      throw networkUnavailable('$what failed: $err');
    }

    final Duration remaining = deadline.difference(DateTime.now());
    final List<int> bytes = await _readCapped(
      streamed,
      what: what,
      // Always allow some time to read, even if connecting consumed the budget: a
      // response that has already arrived should not be thrown away over a
      // millisecond of arithmetic.
      timeout: remaining.isNegative ? const Duration(seconds: 1) : remaining,
    );

    if (streamed.isRedirect) {
      final String? location = streamed.headers['location'];
      throw TrueMedException(
        Codes.badResponse,
        '$what was redirected (${streamed.statusCode}) to '
        '${location ?? 'an unspecified location'}. TrueMed does not follow '
        'redirects, because that would resend your API key to wherever it was '
        'pointed. Set TRUEMED_API_BASE to the final URL instead.',
        status: streamed.statusCode,
      );
    }

    String body;
    try {
      body = utf8.decode(bytes, allowMalformed: false);
    } on FormatException {
      throw badResponse(
        '$what returned ${bytes.length} bytes that are not valid UTF-8, so they '
        'cannot be JSON',
      );
    }

    final ApiResult result = decodeEnvelope(
      status: streamed.statusCode,
      contentType: streamed.headers['content-type'],
      body: body,
      what: what,
    );
    return result;
  }

  /// Read a response body with a size cap and a working timeout.
  ///
  /// Written with an explicit subscription rather than `await for` + `.timeout()`
  /// because a `Future.timeout` does not cancel the work behind it: the socket would
  /// stay open and keep buffering after the caller had given up, which on a phone
  /// juggling a camera preview is a leak that shows up as the app slowing down over
  /// a shift rather than as an obvious failure.
  Future<List<int>> _readCapped(
    http.StreamedResponse streamed, {
    required String what,
    required Duration timeout,
  }) {
    final Completer<List<int>> completer = Completer<List<int>>();
    final List<int> bytes = <int>[];
    StreamSubscription<List<int>>? subscription;
    Timer? timer;

    void fail(Object error) {
      if (completer.isCompleted) return;
      timer?.cancel();
      subscription?.cancel();
      completer.completeError(error);
    }

    timer = Timer(timeout, () {
      fail(networkUnavailable(
        '$what timed out after ${timeout.inSeconds}s while reading the response',
      ));
    });

    subscription = streamed.stream.listen(
      (List<int> chunk) {
        if (completer.isCompleted) return;
        bytes.addAll(chunk);
        if (bytes.length > maxResponseBytes) {
          fail(badResponse(
            '$what returned more than $maxResponseBytes bytes, which no TrueMed '
            'response should; the connection was closed',
          ));
        }
      },
      onError: (Object err) {
        // `HandshakeException` and `CertificateException` both implement
        // `TlsException`, so this one branch covers every TLS failure; testing for
        // them separately afterwards would be unreachable code.
        if (err is TlsException) {
          fail(networkUnavailable(
            '$what lost its secure connection mid-response (${err.message})',
          ));
        } else if (err is SocketException) {
          fail(networkUnavailable('$what was interrupted: ${err.message}'));
        } else {
          fail(networkUnavailable('$what failed while reading: $err'));
        }
      },
      onDone: () {
        if (completer.isCompleted) return;
        timer?.cancel();
        completer.complete(bytes);
      },
      cancelOnError: true,
    );

    return completer.future;
  }

  // ── Verification (public) ──────────────────────────────────────────────────

  /// `GET /api/verify/:productID`.
  ///
  /// The signature is *not* checked by this call — a bare product ID carries no
  /// signature, so `checks.signature` comes back `skipped_no_payload` (§4.4). Use
  /// [verifyPayload] whenever the scanned string is available.
  Future<OnlineVerification> verifyProductId(String productId) async {
    // Encoded even though a valid product ID contains only `[A-Z0-9_]`: this value
    // reaches here from a text field on the pharmacy screen as well as from a QR,
    // and an unencoded `../` or `?` in a path is how a client-side path traversal
    // starts.
    final String encoded = Uri.encodeComponent(productId.trim());
    final ApiResult result = await _get(
      '/api/verify/$encoded',
      what: 'Checking $productId',
    );
    return OnlineVerification.fromData(
      result.data,
      cached: result.cached,
      tookMs: result.tookMs,
    );
  }

  /// `POST /api/verify/payload` — the full scanned string, unmodified.
  ///
  /// [rawPayload] is passed through exactly as scanned. It is not trimmed, upcased
  /// or re-encoded here, because the server verifies the signature over the bytes it
  /// receives (§1.5) and any normalisation on the way would invalidate a signature
  /// over a payload that is in fact authentic.
  Future<OnlineVerification> verifyPayload(String rawPayload) async {
    final ApiResult result = await _post(
      '/api/verify/payload',
      <String, Object?>{'raw_payload': rawPayload},
      what: 'Verifying the scanned code',
    );
    return OnlineVerification.fromData(
      result.data,
      cached: result.cached,
      tookMs: result.tookMs,
    );
  }

  // ── Supply chain (authenticated) ───────────────────────────────────────────

  /// `POST /api/medicine` — mint a unit on chain. Role `manufacturer`.
  ///
  /// Present for completeness and for integration tests. The patient, pharmacy and
  /// regulator screens never call it: minting belongs to the factory-floor tooling
  /// in `qr-generator/`, which holds the signing key that this app deliberately
  /// does not.
  Future<String> registerMedicine({
    required MedicineData medicine,
    required String location,
  }) async {
    final String key = await _authorised('Registering a unit');
    final Map<String, Object?> body = Map<String, Object?>.from(
      medicine.toDict(),
    )..['location'] = validateLocation(location);
    // `contract_version` is derivable and not part of the §4.5 request body.
    body.remove('contract_version');
    final ApiResult result = await _post(
      '/api/medicine',
      body,
      apiKey: key,
      what: 'Registering ${medicine.productId}',
    );
    return result.optionalString('product_id') ?? medicine.productId;
  }

  /// `POST /api/location` — a custody hop. Roles `manufacturer`, `distributor`,
  /// `pharmacy`.
  ///
  /// The transition is validated locally first when [currentStatus] is known, so a
  /// pharmacist scanning a unit that is already `dispensed` gets an immediate,
  /// specific message instead of a round trip ending in `VALIDATION_ERROR`. The
  /// server and the chaincode enforce the same rule; this copy is for the user.
  Future<CustodyEvent> recordLocation({
    required String productId,
    required String location,
    required String status,
    String? currentStatus,
  }) async {
    final String key = await _authorised('Recording custody');
    final String cleanLocation = validateLocation(location);
    if (currentStatus != null) {
      validateTransition(currentStatus, status);
    } else if (!Status.isKnown(status)) {
      throw validationError(
        'status "$status" is not one of ${Status.all.join(', ')}',
      );
    }
    // Checked before the request so the failure names the real problem. A pharmacy
    // key sent with `in_transit` would be refused by the server as FORBIDDEN, which
    // reads as "your key is wrong" rather than "a chemist cannot do that".
    final String? role = roleOfApiKey(key);
    if (role == 'pharmacy' && !pharmacyStatuses.contains(status)) {
      throw validationError(
        'a pharmacy key may only record ${pharmacyStatuses.join(' or ')}, '
        'not $status',
      );
    }
    final ApiResult result = await _post(
      '/api/location',
      <String, Object?>{
        'product_id': validateProductID(productId),
        'location': cleanLocation,
        'status': status,
      },
      apiKey: key,
      what: 'Recording $productId at $cleanLocation',
    );
    return CustodyEvent.fromJson(result.data);
  }

  /// `POST /api/temperature` — one IoT reading. Role `sensor`.
  ///
  /// The app never calls this in normal use; the ESP32 in `iot/` does. It exists
  /// here for the diagnostics screen and for end-to-end tests, and [hmac] is a
  /// required parameter rather than something computed internally because **the app
  /// holds no sensor secret and must not**. A shared HMAC key inside a widely
  /// distributed APK would be extractable by anyone who downloaded it, and forging
  /// cold-chain readings would then need nothing but that APK — which is precisely
  /// the attack the per-sensor HMAC in §4.5 exists to prevent.
  Future<void> submitTemperature({
    required String productId,
    required String sensorId,
    required double temperature,
    required String recordedAt,
    required String nonce,
    required String hmac,
    int? batteryPct,
  }) async {
    final String key = await _authorised('Submitting a temperature reading');
    await _post(
      '/api/temperature',
      <String, Object?>{
        'product_id': productId,
        'sensor_id': validateSensorID(sensorId),
        'temperature': validateTemperature(temperature),
        // Parsed and re-emitted through `stamp` so the wire format is exactly the
        // second-precision UTC the contract specifies, whatever offset the caller
        // supplied. Not `toIso8601String()`: that emits milliseconds, and slicing
        // them off is the timezone bug `stamp`'s own doc comment warns about.
        'recorded_at': stamp(parseInstant('recorded_at', recordedAt)),
        if (batteryPct != null) 'battery_pct': batteryPct,
        'nonce': nonce,
        'hmac': hmac,
      },
      apiKey: key,
      what: 'Submitting a reading from $sensorId',
    );
  }

  // ── Reporting (public) ─────────────────────────────────────────────────────

  /// `POST /api/report` — a counterfeit report. Public, and deliberately so.
  ///
  /// No API key is attached even if one is stored. See the library note: a report is
  /// allowed to be anonymous, and attaching the reporter's key would defeat that
  /// while also leaking the key into every proxy log on the path.
  ///
  /// [rawPayload] is the scanned string exactly as read, which is the single most
  /// valuable field in the report: it lets an investigator re-run verification on
  /// the exact bytes, including a forged signature, months later.
  Future<ReportReceipt> reportCounterfeit({
    required String productId,
    String? rawPayload,
    required String pharmacyName,
    required String district,
    required String state,
    double? lat,
    double? lon,
    String? photoBase64,
    String? notes,
    String? reporterContact,
  }) async {
    final Map<String, Object?> body = <String, Object?>{
      // Not `validateProductID`: a counterfeit's product ID may well be malformed,
      // and refusing to accept a report because the fake was badly made would lose
      // exactly the reports worth having. Length and control characters are still
      // checked, because those are injection vectors rather than data quality.
      'product_id': validateText('product_id', productId),
      'pharmacy_name': validateText('pharmacy_name', pharmacyName),
      'district': validateText('district', district),
      'state': validateText('state', state),
    };
    if (rawPayload != null && rawPayload.isNotEmpty) {
      body['raw_payload'] = rawPayload;
    }
    if (lat != null && lon != null) {
      if (lat.isNaN || lon.isNaN || lat.abs() > 90 || lon.abs() > 180) {
        throw validationError(
          'the location on this report is not a valid latitude and longitude',
        );
      }
      body['lat'] = lat;
      body['lon'] = lon;
    }
    if (photoBase64 != null && photoBase64.isNotEmpty) {
      body['photo_base64'] = photoBase64;
    }
    if (notes != null && notes.trim().isNotEmpty) {
      body['notes'] = validateText('notes', notes);
    }
    // Sent as an explicit null when absent, matching §4.5, so the server can tell
    // "the reporter chose to stay anonymous" from "an old client omitted the field".
    body['reporter_contact'] = reporterContact == null ||
            reporterContact.trim().isEmpty
        ? null
        : validateText('reporter_contact', reporterContact);

    final ApiResult result = await _post(
      '/api/report',
      body,
      what: 'Sending your report',
    );
    return ReportReceipt.fromData(result.data);
  }

  // ── Regulator ──────────────────────────────────────────────────────────────

  /// `POST /api/recall` — one transaction, up to `maxRecallPerTx` units.
  ///
  /// Prefer [recallBatchCompletely] unless you are driving the loop yourself: a
  /// single call to this method on a large batch leaves most of it live on chain.
  Future<RecallResult> recallBatch({
    required String batchNo,
    required String reason,
  }) async {
    final String key = await _authorised('Issuing a recall');
    final ApiResult result = await _post(
      '/api/recall',
      <String, Object?>{
        'batch_no': validateBatchNo(batchNo),
        // Required and non-blank by §4.5: the reason is shown to the pharmacist
        // and to the patient, and a recall with no stated cause is not actionable.
        'reason': validateText('reason', reason),
      },
      apiKey: key,
      what: 'Recalling batch $batchNo',
    );
    return RecallResult.fromData(result.data);
  }

  /// Recall an entire batch, repeating while `more_remaining` is true.
  ///
  /// The chaincode caps one transaction at `maxRecallPerTx` units, so a batch of
  /// 5,000 needs ten calls. A caller that stops early leaves part of a recalled
  /// batch valid on chain, with nothing but the §4.4a `recall_incomplete` alert to
  /// show it — which is why this loop exists rather than being left to each screen.
  ///
  /// [maxCalls] bounds the loop. It is not a safety valve for a buggy server so much
  /// as protection against an infinite one: a backend that always returns
  /// `more_remaining: true` with `recalled: 0` would otherwise spin forever on a
  /// phone in someone's pocket. Progress is required, not just continuation.
  Future<RecallProgress> recallBatchCompletely({
    required String batchNo,
    required String reason,
    int maxCalls = 40,
    void Function(RecallProgress progress)? onProgress,
  }) async {
    int recalled = 0;
    int alreadyRecalled = 0;
    int calls = 0;
    bool complete = false;

    while (calls < maxCalls) {
      final RecallResult result =
          await recallBatch(batchNo: batchNo, reason: reason);
      calls += 1;
      recalled += result.recalled;
      // Only meaningful from the first call; afterwards the units this loop has
      // just recalled would be counted again.
      if (calls == 1) alreadyRecalled = result.alreadyRecalled;

      final RecallProgress progress = RecallProgress(
        batchNo: batchNo,
        recalled: recalled,
        alreadyRecalled: alreadyRecalled,
        calls: calls,
        complete: !result.moreRemaining,
      );
      onProgress?.call(progress);

      if (!result.moreRemaining) {
        complete = true;
        break;
      }
      if (result.recalled == 0) {
        // More remaining, but this call moved nothing. Continuing would loop
        // forever; stopping and reporting incomplete is the honest outcome.
        break;
      }
    }

    return RecallProgress(
      batchNo: batchNo,
      recalled: recalled,
      alreadyRecalled: alreadyRecalled,
      calls: calls,
      complete: complete,
    );
  }

  /// `GET /api/dashboard/cdsco`. Role `regulator`.
  Future<CdscoDashboard> cdscoDashboard({int days = 30, int? limit}) async {
    final String key = await _authorised('Loading the CDSCO dashboard');
    final ApiResult result = await _get(
      '/api/dashboard/cdsco',
      query: _windowQuery(days, limit),
      apiKey: key,
      what: 'Loading the CDSCO dashboard',
    );
    return CdscoDashboard.fromData(result.data);
  }

  /// `GET /api/dashboard/pharma`. Role `pharma` — a manufacturer's own analytics,
  /// *not* a retail chemist's. See §4.2 on the two similarly named roles.
  Future<PharmaDashboard> pharmaDashboard({int days = 30, int? limit}) async {
    final String key = await _authorised('Loading the batch dashboard');
    final ApiResult result = await _get(
      '/api/dashboard/pharma',
      query: _windowQuery(days, limit),
      apiKey: key,
      what: 'Loading the batch dashboard',
    );
    return PharmaDashboard.fromData(result.data);
  }

  /// Clamp the §4.4a query parameters locally rather than letting the server
  /// reject them, so a stale saved filter cannot lock a screen out of loading.
  Map<String, String> _windowQuery(int days, int? limit) {
    final int clampedDays = days < 1 ? 1 : (days > 365 ? 365 : days);
    final Map<String, String> query = <String, String>{
      'days': clampedDays.toString(),
    };
    if (limit != null) {
      final int clamped =
          limit < 1 ? 1 : (limit > maxPageSize ? maxPageSize : limit);
      query['limit'] = clamped.toString();
    }
    return query;
  }

  // ── Trust bundle and probes (public) ───────────────────────────────────────

  /// `GET /api/public-keys` → the trust bundle as a JSON string.
  ///
  /// Returned as text because `TrustBundle.fromJson` is what must see it, and the
  /// caller caches the same text.
  ///
  /// The text is a **re-encode** of the envelope's `data` object, not the bytes off
  /// the wire, and that is safe here for a specific reason worth spelling out
  /// because the opposite rule holds one layer down. A QR payload must be verified
  /// over its received bytes (§1.5), so re-serialising one is a signature bypass. A
  /// trust bundle's root signature is computed over `canonicalJSONBytes({version,
  /// issued_at, keys})` — a canonical re-serialisation of the *parsed* fields, by
  /// definition, in `crypto.py` as much as here. Round-tripping the object through
  /// JSON therefore cannot change what gets verified: whitespace and key order are
  /// discarded by the canonicaliser either way. If that ever stops being true — if
  /// the bundle signature moves to covering received bytes — this method must return
  /// the raw body instead, and nothing else here would tell you.
  Future<String> fetchTrustBundle() async {
    final ApiResult result = await _get(
      '/api/public-keys',
      what: 'Updating the list of trusted manufacturers',
    );
    return jsonEncode(result.data);
  }

  /// `GET /healthz` or `/readyz`.
  ///
  /// A 2xx is the answer; the envelope is parsed only for detail and a parse failure
  /// is ignored. Probes are conventionally allowed to answer with plain text, and
  /// refusing to believe a healthy API because its liveness probe is not wrapped in
  /// `{ok:true}` would be the client being pedantic at the user's expense.
  Future<HealthStatus> health({bool ready = false}) async {
    final String path = ready ? '/readyz' : '/healthz';
    try {
      final ApiResult result = await _get(
        path,
        timeout: healthTimeout,
        what: 'Checking whether TrueMed is reachable',
      );
      return HealthStatus.fromData(result.data);
    } on TrueMedException catch (err) {
      if (err.code == Codes.badResponse && (err.status ?? 500) < 300) {
        return const HealthStatus(ready: true, detail: 'ok');
      }
      rethrow;
    }
  }

  /// True when the API answered a probe. Never throws — this only decides whether
  /// to show an "offline" chip, and a chip must not be able to break a screen.
  Future<bool> isReachable() async {
    try {
      await health();
      return true;
    } on Object {
      return false;
    }
  }

  /// Close the underlying HTTP client, unless it was supplied by the caller.
  void close() {
    if (_ownsClient) _client.close();
  }
}
