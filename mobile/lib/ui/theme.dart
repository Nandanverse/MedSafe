/// Colours, typography and the visual encoding of a verdict.
///
/// # The accessibility constraint that shapes this file
///
/// A verification result must **never** be carried by colour alone. Roughly one in
/// twelve men has a red-green colour vision deficiency, which in India is on the
/// order of forty million people, and the single most important distinction this app
/// makes — green GENUINE against red COUNTERFEIT — is precisely the pair those
/// people cannot reliably separate. An app that showed a coloured card and nothing
/// else would tell a substantial minority of its users the opposite of what it meant
/// while looking perfectly clear to its developers.
///
/// So every severity here ships as a triple: a colour, a **distinct icon shape**,
/// and a text label supplied by the localisations. [severityIcon] and [verdictIcon]
/// exist so that no screen has to invent one, and the icons are chosen to differ in
/// silhouette — a tick inside a shield, a triangle, an octagon — rather than merely
/// in fill. Rendered in greyscale the three states are still distinguishable, which
/// is the test worth applying.
///
/// # Why not a seeded Material 3 scheme for the verdicts
///
/// `ColorScheme.fromSeed` is used for the app's chrome and is the right default
/// there. It is deliberately *not* the source of the verdict colours: a seeded
/// scheme harmonises everything towards the primary hue, which is exactly what you
/// want for buttons and exactly what you do not want for a safety signal. Amber
/// nudged towards blue stops reading as caution. The three severity colours are
/// therefore fixed, specified values, and they are the project's stated palette.
library;

import 'package:flutter/material.dart';

import '../core/rules.dart';

/// The project palette.
///
/// `warn` at #FFB300 rather than a lighter yellow because it has to hold a contrast
/// ratio against white text on a phone held at a pharmacy counter under a tube
/// light, and pale amber does not.
abstract final class TrueMedPalette {
  static const Color brand = Color(0xFF2196F3);
  static const Color ok = Color(0xFF4CAF50);
  static const Color warn = Color(0xFFFFB300);
  static const Color critical = Color(0xFFE53935);

  /// Darker variants, used for text and icons *on* a light container of the same
  /// hue. #4CAF50 on a pale green background is around 2:1 against it, well under
  /// the 4.5:1 that body text needs, so a card cannot simply reuse the headline
  /// colour for its wording.
  static const Color okText = Color(0xFF1B5E20);
  static const Color warnText = Color(0xFF7A4F01);
  static const Color criticalText = Color(0xFFB71C1C);

  static const Color okContainer = Color(0xFFE8F5E9);
  static const Color warnContainer = Color(0xFFFFF8E1);
  static const Color criticalContainer = Color(0xFFFFEBEE);

  /// The development-build banner. Purple because it belongs to no severity and
  /// must not be mistaken for one.
  static const Color development = Color(0xFF6A1B9A);
}

/// Severity colours, reachable from any [BuildContext] via the theme.
///
/// A [ThemeExtension] rather than a set of global constants so that the dark theme
/// can supply different containers without every widget testing the brightness
/// itself — which is the bug that leaves one screen with black text on a dark card.
@immutable
class SeverityColors extends ThemeExtension<SeverityColors> {
  const SeverityColors({
    required this.ok,
    required this.warn,
    required this.critical,
    required this.okContainer,
    required this.warnContainer,
    required this.criticalContainer,
    required this.onOkContainer,
    required this.onWarnContainer,
    required this.onCriticalContainer,
  });

  /// Strong colours, for large text, icons and filled banners.
  final Color ok;
  final Color warn;
  final Color critical;

  /// Tinted backgrounds for cards and list rows.
  final Color okContainer;
  final Color warnContainer;
  final Color criticalContainer;

  /// Text and icon colours *on* the containers above.
  final Color onOkContainer;
  final Color onWarnContainer;
  final Color onCriticalContainer;

  static const SeverityColors light = SeverityColors(
    ok: TrueMedPalette.ok,
    warn: TrueMedPalette.warn,
    critical: TrueMedPalette.critical,
    okContainer: TrueMedPalette.okContainer,
    warnContainer: TrueMedPalette.warnContainer,
    criticalContainer: TrueMedPalette.criticalContainer,
    onOkContainer: TrueMedPalette.okText,
    onWarnContainer: TrueMedPalette.warnText,
    onCriticalContainer: TrueMedPalette.criticalText,
  );

  /// The dark scheme lightens the strong colours and darkens the containers.
  ///
  /// Not the light values reused: #E53935 on a near-black surface is harsh enough
  /// to bloom on an OLED panel, and the pale containers would be blinding in the
  /// dark — which matters because a night-shift pharmacist is a real user.
  static const SeverityColors dark = SeverityColors(
    ok: Color(0xFF81C784),
    warn: Color(0xFFFFCA28),
    critical: Color(0xFFEF5350),
    okContainer: Color(0xFF1B3320),
    warnContainer: Color(0xFF3A2E10),
    criticalContainer: Color(0xFF3A1B1D),
    onOkContainer: Color(0xFFC8E6C9),
    onWarnContainer: Color(0xFFFFECB3),
    onCriticalContainer: Color(0xFFFFCDD2),
  );

  Color strongFor(String severity) => switch (severity) {
        Severity.ok => ok,
        Severity.warn => warn,
        // Anything unrecognised is treated as critical, matching `severityFor`.
        // Erring towards alarm on an unknown value is the correct direction here:
        // an unexpected state on a medicine is not reassuring.
        _ => critical,
      };

  Color containerFor(String severity) => switch (severity) {
        Severity.ok => okContainer,
        Severity.warn => warnContainer,
        _ => criticalContainer,
      };

  Color onContainerFor(String severity) => switch (severity) {
        Severity.ok => onOkContainer,
        Severity.warn => onWarnContainer,
        _ => onCriticalContainer,
      };

  @override
  SeverityColors copyWith({
    Color? ok,
    Color? warn,
    Color? critical,
    Color? okContainer,
    Color? warnContainer,
    Color? criticalContainer,
    Color? onOkContainer,
    Color? onWarnContainer,
    Color? onCriticalContainer,
  }) =>
      SeverityColors(
        ok: ok ?? this.ok,
        warn: warn ?? this.warn,
        critical: critical ?? this.critical,
        okContainer: okContainer ?? this.okContainer,
        warnContainer: warnContainer ?? this.warnContainer,
        criticalContainer: criticalContainer ?? this.criticalContainer,
        onOkContainer: onOkContainer ?? this.onOkContainer,
        onWarnContainer: onWarnContainer ?? this.onWarnContainer,
        onCriticalContainer: onCriticalContainer ?? this.onCriticalContainer,
      );

  @override
  SeverityColors lerp(SeverityColors? other, double t) {
    if (other == null) return this;
    return SeverityColors(
      ok: Color.lerp(ok, other.ok, t)!,
      warn: Color.lerp(warn, other.warn, t)!,
      critical: Color.lerp(critical, other.critical, t)!,
      okContainer: Color.lerp(okContainer, other.okContainer, t)!,
      warnContainer: Color.lerp(warnContainer, other.warnContainer, t)!,
      criticalContainer:
          Color.lerp(criticalContainer, other.criticalContainer, t)!,
      onOkContainer: Color.lerp(onOkContainer, other.onOkContainer, t)!,
      onWarnContainer: Color.lerp(onWarnContainer, other.onWarnContainer, t)!,
      onCriticalContainer:
          Color.lerp(onCriticalContainer, other.onCriticalContainer, t)!,
    );
  }
}

/// Read the severity colours off the theme.
///
/// Falls back to [SeverityColors.light] rather than throwing on a missing
/// extension, so that a widget rendered in a bare `MaterialApp` — as happens in a
/// widget test — still gets sane colours instead of a null dereference.
SeverityColors severityColorsOf(BuildContext context) =>
    Theme.of(context).extension<SeverityColors>() ?? SeverityColors.light;

/// The icon for a severity. Shapes, not just colours — see the library note.
IconData severityIcon(String severity) => switch (severity) {
      Severity.ok => Icons.verified_user_outlined,
      Severity.warn => Icons.warning_amber_rounded,
      _ => Icons.dangerous_outlined,
    };

/// A per-verdict icon, so that two verdicts of the same severity are still
/// distinguishable at a glance.
///
/// This matters most for the three critical verdicts: COUNTERFEIT, RECALLED and
/// COLD_CHAIN_BREACH all render red, and they call for completely different actions
/// — report it, return it, do not administer it. A single red octagon for all three
/// would flatten that distinction into the wording alone, which is the part people
/// skip when they are alarmed.
IconData verdictIcon(String verdict) => switch (verdict) {
      Verdict.genuine => Icons.verified_user,
      Verdict.offlineOk => Icons.wifi_off_rounded,
      Verdict.expired => Icons.event_busy_rounded,
      Verdict.coldChain => Icons.thermostat_rounded,
      Verdict.clone => Icons.content_copy_rounded,
      Verdict.recalled => Icons.block_rounded,
      Verdict.counterfeit => Icons.dangerous_rounded,
      Verdict.unverifiable => Icons.help_outline_rounded,
      // An unknown verdict from a newer API. A question mark rather than a red
      // octagon: the colour already says critical, and claiming to know *which*
      // critical thing it is would be a lie.
      _ => Icons.help_outline_rounded,
    };

abstract final class TrueMedTheme {
  static ThemeData light() => _build(Brightness.light);
  static ThemeData dark() => _build(Brightness.dark);

  /// The shape every card uses. See the note in [_build] on why this is not a
  /// `cardTheme`.
  static ShapeBorder cardShape(ColorScheme scheme) => RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: BorderSide(color: scheme.outlineVariant),
      );

  static ThemeData _build(Brightness brightness) {
    final ColorScheme scheme = ColorScheme.fromSeed(
      seedColor: TrueMedPalette.brand,
      brightness: brightness,
    );
    final bool isDark = brightness == Brightness.dark;

    return ThemeData(
      useMaterial3: true,
      colorScheme: scheme,
      extensions: <ThemeExtension<dynamic>>[
        isDark ? SeverityColors.dark : SeverityColors.light,
      ],
      scaffoldBackgroundColor: scheme.surface,
      appBarTheme: AppBarTheme(
        backgroundColor: scheme.surface,
        foregroundColor: scheme.onSurface,
        elevation: 0,
        scrolledUnderElevation: 2,
        centerTitle: false,
      ),
      // No `cardTheme` here, on purpose. The type of `ThemeData.cardTheme` changed
      // from `CardTheme` to `CardThemeData` partway through Flutter's 3.x line (as
      // did `DialogTheme` and `TabBarTheme`), so a literal of either name compiles
      // on some SDKs and not others. Since this project's whole point is that it
      // builds on a student's machine without a version hunt, card styling lives in
      // [cardShape] and is applied by `TrueMedCard` instead. Nothing is lost: it was
      // one shape and one elevation.
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          // 48dp minimum: the Material touch-target size, and the reason the
          // default 40dp is not used is that the primary action on the verdict
          // screen is "report this medicine", often pressed by someone who is
          // upset, in a hurry, or holding a strip in the other hand.
          minimumSize: const Size.fromHeight(48),
          textStyle: const TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          minimumSize: const Size.fromHeight(48),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: scheme.surfaceContainerHighest,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide.none,
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide(color: scheme.outlineVariant),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide(color: scheme.primary, width: 2),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide(color: scheme.error, width: 2),
        ),
      ),
      listTileTheme: const ListTileThemeData(
        contentPadding: EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      ),
      dividerTheme: DividerThemeData(
        color: scheme.outlineVariant,
        space: 1,
        thickness: 1,
      ),
      chipTheme: ChipThemeData(
        side: BorderSide(color: scheme.outlineVariant),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
        ),
      ),
      snackBarTheme: SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
        ),
      ),
      textTheme: _textTheme(scheme),
    );
  }

  /// Type scale, with the verdict headline enlarged.
  ///
  /// `displaySmall` is the verdict word itself and is set well above the Material
  /// default. The screen it appears on has one job, is read at arm's length, and is
  /// frequently read in a hurry by someone who has just been told their medicine
  /// might be fake. Nothing else on that screen competes with it.
  static TextTheme _textTheme(ColorScheme scheme) => TextTheme(
        displaySmall: TextStyle(
          fontSize: 34,
          height: 1.15,
          fontWeight: FontWeight.w700,
          letterSpacing: -0.5,
          color: scheme.onSurface,
        ),
        headlineSmall: TextStyle(
          fontSize: 22,
          fontWeight: FontWeight.w600,
          color: scheme.onSurface,
        ),
        titleMedium: TextStyle(
          fontSize: 16,
          fontWeight: FontWeight.w600,
          color: scheme.onSurface,
        ),
        bodyLarge: TextStyle(
          fontSize: 16,
          height: 1.45,
          color: scheme.onSurface,
        ),
        bodyMedium: TextStyle(
          fontSize: 14,
          height: 1.45,
          color: scheme.onSurfaceVariant,
        ),
        labelLarge: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600),
        // Used for product IDs, fingerprints and batch numbers. Monospace so that
        // an O and a 0 in a product ID are distinguishable when someone reads one
        // aloud over the phone to a distributor.
        labelSmall: TextStyle(
          fontFamily: 'monospace',
          fontFamilyFallback: const <String>['Roboto Mono', 'monospace'],
          fontSize: 12,
          color: scheme.onSurfaceVariant,
        ),
      );
}
