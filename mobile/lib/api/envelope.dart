/// The `{ok, data, meta}` / `{ok, error}` envelope from DATA-CONTRACT.md §4.1.
///
/// This file contains no I/O. It takes a status code, a content type and a body
/// string, and either returns the `data` object or throws a [TrueMedException]
/// carrying the contract's own `error.code`. Keeping it separate from the HTTP
/// client means every branch here is testable with a string literal and no socket,
/// which matters because the interesting cases are the malformed ones.
///
/// # What this refuses, and why it is not paranoia
///
/// The app is used on hotel, railway-station and hospital Wi-Fi, all of which
/// commonly run captive portals. A captive portal answers *every* request with
/// `200 OK` and an HTML login page. A decoder that trusted the status code and
/// then did `json['data']['verdict']` would read `null` out of that and, depending
/// on how the caller handled it, either crash or produce a verdict from nothing.
/// So the envelope is validated positively: `ok` must be present and boolean, the
/// content type must be JSON, and anything else is [Codes.badResponse] — which the
/// UI renders as "could not reach TrueMed", not as a statement about the medicine.
library;

import 'dart:convert';

import '../core/errors.dart';

/// Largest response body accepted, in bytes.
///
/// A cap is needed because the app is not the only thing that can answer a
/// request: a misconfigured proxy or a hostile network can stream indefinitely,
/// and `http`'s convenience methods buffer the whole body in memory before anyone
/// gets to look at it. Four mebibytes is far above the largest legitimate response
/// (a CDSCO dashboard page, or a trust bundle of a few thousand keys) and far
/// below what would trouble a 2GB Android Go device.
///
/// Note the real limit this implies: a trust bundle much past roughly ten thousand
/// manufacturer keys will not fit, and `GET /api/public-keys` would need paging
/// before that point. That is a genuine scaling ceiling and is recorded here rather
/// than discovered later.
const int maxResponseBytes = 4 * 1024 * 1024;

/// A successful envelope, unwrapped.
class ApiResult {
  const ApiResult({
    required this.data,
    required this.status,
    this.cached = false,
    this.tookMs,
  });

  /// The `data` object. Always a map; endpoints that return a list wrap it.
  final Map<String, Object?> data;

  final int status;

  /// `meta.cached` — true when the API served this from Redis rather than from
  /// Fabric. Surfaced in the UI because a cached answer can be up to an hour old
  /// (§4.6), and "verified 40 minutes ago" is a different claim from "verified
  /// just now" when the question is whether a recall has landed.
  final bool cached;

  /// `meta.took_ms`, for the diagnostics screen.
  final int? tookMs;

  /// Read a required child object.
  Map<String, Object?> object(String key) {
    final Object? value = data[key];
    if (value is! Map) {
      throw badResponse(
        "the API response is missing the '$key' object, or it is not an object",
      );
    }
    return value.cast<String, Object?>();
  }

  /// Read an optional child object.
  Map<String, Object?>? optionalObject(String key) {
    final Object? value = data[key];
    if (value == null) return null;
    if (value is! Map) {
      throw badResponse("the API response has a non-object '$key'");
    }
    return value.cast<String, Object?>();
  }

  /// Read an optional child array, defaulting to empty.
  List<Object?> array(String key) {
    final Object? value = data[key];
    if (value == null) return const <Object?>[];
    if (value is! List) {
      throw badResponse("the API response has a non-array '$key'");
    }
    return value;
  }

  String string(String key) {
    final Object? value = data[key];
    if (value is! String || value.isEmpty) {
      throw badResponse("the API response is missing the '$key' string");
    }
    return value;
  }

  String? optionalString(String key) {
    final Object? value = data[key];
    if (value == null) return null;
    if (value is! String) {
      throw badResponse("the API response has a non-string '$key'");
    }
    return value;
  }

  /// An integer, tolerating the JSON `4.0` that some encoders emit for a whole
  /// number. A fractional value is a contract violation and is refused rather
  /// than truncated: a scan count of `25.7` means something upstream is wrong,
  /// and silently reading it as 25 would hide that at exactly the threshold
  /// where the clone rule fires.
  int? optionalInt(String key) {
    final Object? value = data[key];
    if (value == null) return null;
    if (value is int) return value;
    if (value is double && value.isFinite && value == value.roundToDouble()) {
      return value.toInt();
    }
    throw badResponse("the API response has a non-integer '$key' ($value)");
  }

  bool boolean(String key, {bool orElse = false}) {
    final Object? value = data[key];
    if (value == null) return orElse;
    if (value is bool) return value;
    throw badResponse("the API response has a non-boolean '$key'");
  }
}

/// Map an HTTP status onto a contract error code, for responses whose body is not
/// a usable envelope.
///
/// This exists because the API is rarely the only thing on the path. A reverse
/// proxy enforcing rate limits returns `429` with an HTML body; a load balancer
/// with no healthy backend returns `503` the same way. Both are meaningful and
/// neither is [Codes.badResponse]. In particular `503` maps to
/// [Codes.upstreamUnavailable], for which `isTransportFailure` is true, so the app
/// degrades to offline verification instead of showing an error — which is the
/// correct behaviour and would be lost if every unparseable body were treated the
/// same.
String codeForStatus(int status) {
  switch (status) {
    case 401:
      return Codes.unauthorized;
    case 403:
      return Codes.forbidden;
    case 404:
      return Codes.notFound;
    case 409:
      return Codes.conflict;
    case 429:
      return Codes.rateLimited;
    case 502:
    case 503:
    case 504:
      return Codes.upstreamUnavailable;
    default:
      return status >= 500 ? Codes.internalError : Codes.badResponse;
  }
}

/// True when [contentType] names a JSON body.
///
/// Accepts any `+json` suffix as well as `application/json`, and ignores
/// parameters such as `; charset=utf-8`. A null content type is accepted, because
/// some minimal servers omit it and the body is validated anyway; an explicitly
/// non-JSON type is not, because that is the captive-portal signature.
bool looksLikeJson(String? contentType) {
  if (contentType == null || contentType.isEmpty) return true;
  final String type = contentType.split(';').first.trim().toLowerCase();
  return type == 'application/json' ||
      type == 'text/json' ||
      type.endsWith('+json');
}

/// A short, safe excerpt of a body for an error message.
///
/// Control characters are stripped rather than escaped, and the result is clipped,
/// because this string ends up in logs and in a diagnostics screen. An HTML login
/// page pasted whole into a log is unreadable; its first eighty characters are
/// enough to recognise one.
String bodyExcerpt(String body, {int max = 80}) {
  final StringBuffer out = StringBuffer();
  int written = 0;
  for (final int rune in body.trim().runes) {
    if (written >= max) {
      out.write('...');
      break;
    }
    // Control characters and DEL/C1 become a space, so a minified HTML page with
    // embedded newlines stays on one line in a log.
    final bool isControl = rune < 0x20 || (rune >= 0x7f && rune <= 0x9f);
    out.writeCharCode(isControl ? 0x20 : rune);
    written += 1;
  }
  return out.toString();
}

/// Unwrap an envelope, or throw.
///
/// [what] names the call — `GET /api/verify/...` — so a failure says which request
/// failed without the caller having to catch and re-wrap.
ApiResult decodeEnvelope({
  required int status,
  required String? contentType,
  required String body,
  required String what,
}) {
  if (!looksLikeJson(contentType)) {
    throw TrueMedException(
      // A non-JSON body on an otherwise fine status is almost always a captive
      // portal, so the message names that rather than talking about content types.
      status >= 400 ? codeForStatus(status) : Codes.badResponse,
      '$what returned $contentType instead of JSON. This usually means a Wi-Fi '
      'login page answered instead of TrueMed. Response began: '
      '"${bodyExcerpt(body)}"',
      status: status,
    );
  }

  if (body.trim().isEmpty) {
    throw TrueMedException(
      status >= 400 ? codeForStatus(status) : Codes.badResponse,
      '$what returned an empty body with status $status',
      status: status,
    );
  }

  Object? decoded;
  try {
    decoded = jsonDecode(body);
  } on FormatException catch (err) {
    throw TrueMedException(
      status >= 400 ? codeForStatus(status) : Codes.badResponse,
      '$what did not return valid JSON (${err.message}). Response began: '
      '"${bodyExcerpt(body)}"',
      status: status,
    );
  }

  if (decoded is! Map) {
    throw TrueMedException(
      status >= 400 ? codeForStatus(status) : Codes.badResponse,
      '$what returned ${decoded.runtimeType} at the top level; every TrueMed '
      'response is a JSON object',
      status: status,
    );
  }

  final Object? ok = decoded['ok'];
  if (ok is! bool) {
    // The envelope is mandatory in both directions (§4.1), so its absence means
    // this is not the TrueMed API answering, whatever the status says.
    throw TrueMedException(
      status >= 400 ? codeForStatus(status) : Codes.badResponse,
      "$what returned a JSON object with no boolean 'ok' field, so it is not a "
      'TrueMed API response. Response began: "${bodyExcerpt(body)}"',
      status: status,
    );
  }

  if (!ok) {
    final Object? error = decoded['error'];
    if (error is! Map) {
      throw TrueMedException(
        codeForStatus(status),
        '$what failed with status $status but did not say why '
        "(no 'error' object)",
        status: status,
      );
    }
    final Object? rawCode = error['code'];
    final Object? rawMessage = error['message'];
    // An unrecognised code is not discarded — it is reported inside the message
    // and demoted to a code this build can act on. The API is allowed to be newer
    // than the installed APK, and `TrueMedException` maps anything unknown to
    // INTERNAL_ERROR, which would otherwise erase the one piece of information a
    // developer reading a bug report actually needs.
    final bool knownCode = rawCode is String && Codes.isKnown(rawCode);
    final String code =
        knownCode ? rawCode as String : codeForStatus(status);
    final String message = rawMessage is String && rawMessage.isNotEmpty
        ? rawMessage
        : '$what failed with status $status';
    throw TrueMedException(
      code,
      knownCode
          ? message
          : '$message (the API reported code '
              '"${rawCode is String ? rawCode : rawCode.runtimeType}", which '
              'this version of TrueMed does not recognise)',
      details: error['details'],
      status: status,
    );
  }

  // ok == true, but a 4xx/5xx alongside it means the two halves of the response
  // disagree. Trusting `ok` here would let a proxy's error page with an injected
  // `{"ok":true}` through; trusting the status would break a legitimate 201.
  if (status >= 400) {
    throw TrueMedException(
      codeForStatus(status),
      '$what returned status $status with "ok": true, which contradicts itself',
      status: status,
    );
  }

  final Object? data = decoded['data'];
  if (data is! Map) {
    throw badResponse(
      "$what succeeded but returned no 'data' object",
    );
  }

  final Object? meta = decoded['meta'];
  bool cached = false;
  int? tookMs;
  if (meta is Map) {
    final Object? rawCached = meta['cached'];
    if (rawCached is bool) cached = rawCached;
    final Object? rawTook = meta['took_ms'];
    if (rawTook is int) {
      tookMs = rawTook;
    } else if (rawTook is double && rawTook.isFinite) {
      tookMs = rawTook.round();
    }
  }

  return ApiResult(
    data: data.cast<String, Object?>(),
    status: status,
    cached: cached,
    tookMs: tookMs,
  );
}
