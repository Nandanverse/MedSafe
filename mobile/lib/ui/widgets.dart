/// Widgets shared by every screen.
///
/// # Why these exist rather than being inlined per screen
///
/// Three of them enforce rules that are easy to break by accident, and putting the
/// rule inside a widget is the only way to make breaking it require effort:
///
///  * [SeverityBanner] cannot be constructed without a text label, so the
///    colour-only encoding that `theme.dart`'s library note warns about is
///    structurally impossible to ship.
///  * [BusyButton] disables itself while its action is in flight. Two of this app's
///    actions — filing a report and starting a recall — are not idempotent, and a
///    double tap on a slow connection is the normal way a user produces two of
///    something they wanted one of.
///  * [ErrorView] takes a `TrueMedException` and renders a sentence. It deliberately
///    has no path that produces a verdict, because the failure it most often shows is
///    a transport failure, and "no internet" must never be allowed to look like a
///    statement about the medicine.
///
/// The rest are here to stop nine screens each inventing their own padding.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show Clipboard, ClipboardData;

import '../config.dart';
import '../core/errors.dart';
// `isDevelopmentRootKey` lives here rather than in config.dart, and config.dart does
// not re-export it — see the note at the top of config.dart on why the core must be
// importable without the app layers.
import '../core/pinned_root_key.dart';
import '../core/rules.dart';
import '../l10n/strings.dart';
import 'theme.dart';

/// Standard horizontal page padding. 16dp, matching the list tile theme so that a
/// card and a list row on the same screen line up on the left edge.
const EdgeInsets pagePadding = EdgeInsets.symmetric(horizontal: 16, vertical: 12);

/// A bordered, flat card.
///
/// Flat rather than elevated because there are up to five of these stacked on the
/// verdict screen, and five drop shadows down a phone screen reads as noise. The
/// shape comes from [TrueMedTheme.cardShape] — see the note in `theme.dart` on why
/// this is not a `cardTheme`.
class TrueMedCard extends StatelessWidget {
  const TrueMedCard({
    super.key,
    required this.child,
    this.color,
    this.padding = const EdgeInsets.all(16),
    this.margin = const EdgeInsets.only(bottom: 12),
    this.onTap,
  });

  final Widget child;
  final Color? color;
  final EdgeInsetsGeometry padding;
  final EdgeInsetsGeometry margin;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final ColorScheme scheme = Theme.of(context).colorScheme;
    final ShapeBorder shape = TrueMedTheme.cardShape(scheme);
    final Widget content = Padding(padding: padding, child: child);

    return Padding(
      padding: margin,
      child: Material(
        color: color ?? scheme.surface,
        shape: shape,
        clipBehavior: Clip.antiAlias,
        child: onTap == null
            ? content
            : InkWell(onTap: onTap, child: content),
      ),
    );
  }
}

/// The verdict banner: colour, icon shape and words, always all three.
///
/// [label] is required and not defaulted. A default would be a way to omit it, and
/// omitting it is the accessibility defect this widget exists to prevent — for the
/// roughly one in twelve men with a red-green deficiency, a green card and a red card
/// are the same card.
class SeverityBanner extends StatelessWidget {
  const SeverityBanner({
    super.key,
    required this.severity,
    required this.label,
    this.detail,
    this.action,
    this.icon,
    this.dense = false,
  });

  /// One of [Severity]. An unrecognised value renders as critical, matching
  /// `severityFor`.
  final String severity;

  /// The headline. The largest text on the screen when [dense] is false.
  final String label;

  /// One or two sentences of explanation.
  final String? detail;

  /// What to do about it. Rendered in bold, because it is the part that changes an
  /// outcome and the part users skip.
  final String? action;

  /// Overrides [severityIcon]. The verdict screen passes [verdictIcon] so that three
  /// different critical verdicts do not all show the same octagon.
  final IconData? icon;

  /// Compact form, for a list row rather than a full screen.
  final bool dense;

  @override
  Widget build(BuildContext context) {
    final SeverityColors colors = severityColorsOf(context);
    final TextTheme text = Theme.of(context).textTheme;
    final Color fg = colors.onContainerFor(severity);

    return Container(
      width: double.infinity,
      padding: EdgeInsets.all(dense ? 12 : 20),
      decoration: BoxDecoration(
        color: colors.containerFor(severity),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: colors.strongFor(severity), width: 2),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Icon(
            icon ?? severityIcon(severity),
            color: colors.strongFor(severity),
            size: dense ? 24 : 40,
          ),
          SizedBox(width: dense ? 12 : 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Text(
                  label,
                  style: (dense ? text.titleMedium : text.displaySmall)
                      ?.copyWith(color: fg),
                ),
                if (detail != null) ...<Widget>[
                  const SizedBox(height: 8),
                  Text(
                    detail!,
                    style: text.bodyLarge?.copyWith(color: fg),
                  ),
                ],
                if (action != null) ...<Widget>[
                  const SizedBox(height: 12),
                  Text(
                    action!,
                    style: text.bodyLarge?.copyWith(
                      color: fg,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}

/// A small severity pill, for history rows and dashboard tables.
class SeverityChip extends StatelessWidget {
  const SeverityChip({super.key, required this.severity, required this.label});

  final String severity;
  final String label;

  @override
  Widget build(BuildContext context) {
    final SeverityColors colors = severityColorsOf(context);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: colors.containerFor(severity),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: colors.strongFor(severity)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: <Widget>[
          Icon(
            severityIcon(severity),
            size: 14,
            color: colors.onContainerFor(severity),
          ),
          const SizedBox(width: 6),
          Text(
            label,
            style: Theme.of(context).textTheme.labelLarge?.copyWith(
                  color: colors.onContainerFor(severity),
                  fontSize: 12,
                ),
          ),
        ],
      ),
    );
  }
}

/// The development-build warning.
///
/// Not dismissible, on purpose. A build pinned to a published test key can be fooled
/// by anyone who reads the repository, and a warning the user tapped away once is
/// worse than no warning at all: from then on the app looks like the real thing. It
/// costs one strip of screen and it is the honest cost of shipping a demo build that
/// says "GENUINE" in green.
///
/// Renders nothing in a release build with a real pinned root and HTTPS.
class DevBuildBanner extends StatelessWidget {
  const DevBuildBanner({super.key});

  @override
  Widget build(BuildContext context) {
    if (!isDevelopmentBuild) return const SizedBox.shrink();
    final Strings s = Strings.of(context);
    // A published root key is the more serious of the two conditions: it means
    // verification itself can be forged. Plain HTTP only exposes what you scanned.
    final bool forgeable = isDevelopmentRootKey;

    return Material(
      color: TrueMedPalette.development,
      child: InkWell(
        onTap: () => showDialog<void>(
          context: context,
          builder: (BuildContext context) => AlertDialog(
            title: Text(forgeable
                ? s.devBuildTitle
                : s.insecureTransportTitle),
            content: Text(forgeable ? s.devBuildBody : s.insecureTransportBody),
            actions: <Widget>[
              TextButton(
                onPressed: () => Navigator.of(context).pop(),
                child: Text(s.close),
              ),
            ],
          ),
        ),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          child: Row(
            children: <Widget>[
              const Icon(Icons.science_outlined, color: Colors.white, size: 18),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  forgeable ? s.devBuildTitle : s.insecureTransportTitle,
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              const Icon(Icons.info_outline, color: Colors.white70, size: 16),
            ],
          ),
        ),
      ),
    );
  }
}

/// A label above a value. The app's basic unit of detail display.
class LabelledValue extends StatelessWidget {
  const LabelledValue({
    super.key,
    required this.label,
    required this.value,
    this.mono = false,
    this.valueColor,
    this.copyable = false,
  });

  final String label;
  final String value;

  /// Monospace, for product IDs, batch numbers, licence numbers and fingerprints.
  final bool mono;

  final Color? valueColor;

  /// Adds a copy button. Used for product IDs and report reference numbers, which
  /// people need to paste into an email or read out over a phone.
  final bool copyable;

  @override
  Widget build(BuildContext context) {
    final TextTheme text = Theme.of(context).textTheme;
    final ColorScheme scheme = Theme.of(context).colorScheme;
    final TextStyle? valueStyle = mono
        ? text.labelSmall?.copyWith(
            fontSize: 14,
            color: valueColor ?? scheme.onSurface,
          )
        : text.bodyLarge?.copyWith(color: valueColor);

    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Text(
            label,
            style: text.bodyMedium?.copyWith(
              fontSize: 12,
              color: scheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 2),
          if (copyable)
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Expanded(child: SelectableText(value, style: valueStyle)),
                IconButton(
                  icon: const Icon(Icons.copy_rounded, size: 18),
                  tooltip: 'Copy',
                  visualDensity: VisualDensity.compact,
                  onPressed: () async {
                    await Clipboard.setData(ClipboardData(text: value));
                    if (!context.mounted) return;
                    showTrueMedSnack(context, 'Copied');
                  },
                ),
              ],
            )
          else
            Text(value, style: valueStyle),
        ],
      ),
    );
  }
}

/// A heading between sections of a scrolling screen.
class SectionHeader extends StatelessWidget {
  const SectionHeader({super.key, required this.title, this.trailing, this.icon});

  final String title;
  final Widget? trailing;
  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(top: 8, bottom: 8),
      child: Row(
        children: <Widget>[
          if (icon != null) ...<Widget>[
            Icon(icon, size: 18, color: Theme.of(context).colorScheme.primary),
            const SizedBox(width: 8),
          ],
          Expanded(
            child: Text(title, style: Theme.of(context).textTheme.titleMedium),
          ),
          if (trailing != null) trailing!,
        ],
      ),
    );
  }
}

/// A big metric, for the two dashboards.
class MetricTile extends StatelessWidget {
  const MetricTile({
    super.key,
    required this.label,
    required this.value,
    this.severity,
    this.icon,
  });

  final String label;
  final String value;

  /// When set, tints the tile. Null means neutral — the count of units made is not
  /// good or bad news, and colouring it would spend the user's attention on nothing.
  final String? severity;

  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    final ColorScheme scheme = Theme.of(context).colorScheme;
    final SeverityColors colors = severityColorsOf(context);
    final bool tinted = severity != null;
    final Color fg =
        tinted ? colors.onContainerFor(severity!) : scheme.onSurface;

    return TrueMedCard(
      margin: EdgeInsets.zero,
      padding: const EdgeInsets.all(14),
      color: tinted ? colors.containerFor(severity!) : scheme.surface,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Row(
            children: <Widget>[
              if (icon != null) ...<Widget>[
                Icon(icon, size: 16, color: fg),
                const SizedBox(width: 6),
              ],
              Expanded(
                child: Text(
                  label,
                  style: Theme.of(context)
                      .textTheme
                      .bodyMedium
                      ?.copyWith(fontSize: 12, color: fg),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            value,
            style: Theme.of(context)
                .textTheme
                .headlineSmall
                ?.copyWith(fontSize: 26, color: fg),
          ),
        ],
      ),
    );
  }
}

/// A button that runs an async action and blocks a second tap while it runs.
///
/// The two actions this protects are worth naming: `POST /api/report` creates a new
/// report every time it is called, and a recall walks the batch in 500-unit
/// transactions. Neither is idempotent, and both are slow enough on a rural
/// connection that a second tap feels reasonable to the person tapping.
///
/// The `mounted` guards are not decoration. An action that navigates away on success
/// — which the report screen does — disposes this widget while `onPressed` is still
/// awaiting, and a `setState` after that throws.
class BusyButton extends StatefulWidget {
  const BusyButton({
    super.key,
    required this.label,
    required this.onPressed,
    this.icon,
    this.destructive = false,
    this.enabled = true,
  });

  final String label;

  /// Null disables the button, as with any Material button.
  final Future<void> Function()? onPressed;

  final IconData? icon;

  /// Renders in the error colour. Used for "recall this batch", which is
  /// irreversible.
  final bool destructive;

  final bool enabled;

  @override
  State<BusyButton> createState() => _BusyButtonState();
}

class _BusyButtonState extends State<BusyButton> {
  bool _busy = false;

  Future<void> _run() async {
    final Future<void> Function()? action = widget.onPressed;
    if (action == null || _busy) return;
    setState(() => _busy = true);
    try {
      await action();
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final ColorScheme scheme = Theme.of(context).colorScheme;
    final bool on = widget.enabled && widget.onPressed != null && !_busy;

    return FilledButton(
      onPressed: on ? _run : null,
      style: widget.destructive
          ? FilledButton.styleFrom(
              backgroundColor: scheme.error,
              foregroundColor: scheme.onError,
              minimumSize: const Size.fromHeight(48),
              textStyle:
                  const TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
            )
          : null,
      child: _busy
          ? const SizedBox(
              height: 20,
              width: 20,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : Row(
              mainAxisSize: MainAxisSize.min,
              children: <Widget>[
                if (widget.icon != null) ...<Widget>[
                  Icon(widget.icon, size: 20),
                  const SizedBox(width: 8),
                ],
                Text(widget.label),
              ],
            ),
    );
  }
}

/// A blank state with an explanation and an optional action.
class EmptyState extends StatelessWidget {
  const EmptyState({
    super.key,
    required this.icon,
    required this.title,
    this.body,
    this.action,
  });

  final IconData icon;
  final String title;
  final String? body;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    final ColorScheme scheme = Theme.of(context).colorScheme;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            Icon(icon, size: 56, color: scheme.onSurfaceVariant),
            const SizedBox(height: 16),
            Text(
              title,
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            if (body != null) ...<Widget>[
              const SizedBox(height: 8),
              Text(
                body!,
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodyMedium,
              ),
            ],
            if (action != null) ...<Widget>[
              const SizedBox(height: 24),
              action!,
            ],
          ],
        ),
      ),
    );
  }
}

/// Renders a failure as a sentence a user can act on.
///
/// Every branch here is amber or neutral. None is red, and none produces a verdict.
/// That is the point: the commonest thing this widget shows is a timeout, and an app
/// that painted a timeout red would teach its users that red means "try again",
/// which is exactly the lesson that gets a counterfeit swallowed.
class ErrorView extends StatelessWidget {
  const ErrorView({
    super.key,
    required this.error,
    this.onRetry,
    this.onSignIn,
    this.compact = false,
  });

  final Object error;

  final Future<void> Function()? onRetry;

  /// Offered when the failure is an auth failure, so an expired key leads to the
  /// sign-in screen rather than to a dead end.
  final VoidCallback? onSignIn;

  final bool compact;

  /// The headline and body for a failure. Public because the report screen shows the
  /// same wording inside a dialog rather than as a full page.
  static (String, String) describe(BuildContext context, Object error) {
    final Strings s = Strings.of(context);
    if (error is! TrueMedException) {
      return (s.somethingWentWrong, error.toString());
    }
    if (error.isTransportFailure) {
      return (s.offlineTitle, s.offlineBody);
    }
    switch (error.code) {
      case Codes.unauthorized:
        return ('Sign in again', 'This device\'s API key was not accepted. '
            'It may have been revoked or replaced.');
      case Codes.forbidden:
        // Worth its own wording: the user is signed in and the key is valid, so
        // "sign in again" would send them round a loop that cannot succeed.
        return ('Not allowed with this key', error.message);
      case Codes.rateLimited:
        return ('Too many requests', 'The server is asking us to slow down. '
            'Wait a moment and try again.');
      case Codes.notFound:
        return ('Not found', error.message);
      case Codes.badResponse:
        return ('Unexpected reply from the server',
            'TrueMed could not read what the server sent. This usually means the '
            'app and the server are different versions. ${error.message}');
      case Codes.validationError:
        return ('Check the details', error.message);
      default:
        return (s.somethingWentWrong, error.message);
    }
  }

  @override
  Widget build(BuildContext context) {
    final Strings s = Strings.of(context);
    final (String title, String body) = describe(context, error);

    // Copied to a local because Dart does not promote a public instance field: a
    // bare `error is TrueMedException && error.isAuthFailure` would not compile.
    final Object err = error;
    final bool auth = err is TrueMedException && err.isAuthFailure;
    final bool transport = err is TrueMedException && err.isTransportFailure;

    final List<Widget> actions = <Widget>[
      if (onRetry != null)
        BusyButton(label: s.retry, icon: Icons.refresh, onPressed: onRetry),
      if (auth && onSignIn != null) ...<Widget>[
        const SizedBox(height: 8),
        OutlinedButton(onPressed: onSignIn, child: Text(s.signIn)),
      ],
    ];

    if (compact) {
      final SeverityColors colors = severityColorsOf(context);
      // Amber, always — see the class note. Read through `containerFor` rather than
      // the `warnContainer` field so that this row uses the same lookup every
      // severity-coloured surface in the app uses.
      final Color bg = colors.containerFor(Severity.warn);
      final Color fg = colors.onContainerFor(Severity.warn);
      return TrueMedCard(
        color: bg,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Icon(Icons.info_outline, color: fg),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      Text(
                        title,
                        style: Theme.of(context)
                            .textTheme
                            .titleMedium
                            ?.copyWith(color: fg),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        body,
                        style: Theme.of(context)
                            .textTheme
                            .bodyMedium
                            ?.copyWith(color: fg),
                      ),
                    ],
                  ),
                ),
              ],
            ),
            if (actions.isNotEmpty) ...<Widget>[
              const SizedBox(height: 12),
              ...actions,
            ],
          ],
        ),
      );
    }

    return EmptyState(
      icon: transport ? Icons.wifi_off_rounded : Icons.error_outline,
      title: title,
      body: body,
      action: actions.isEmpty
          ? null
          : Column(mainAxisSize: MainAxisSize.min, children: actions),
    );
  }
}

/// A full-screen loading state with a line of text.
///
/// The text is required. An unlabelled spinner on a screen that verifies medicine
/// leaves the user unable to tell "contacting the server" from "checking the
/// signature", and those fail in different ways and take very different times.
class BusyView extends StatelessWidget {
  const BusyView({super.key, required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: <Widget>[
          const CircularProgressIndicator(),
          const SizedBox(height: 20),
          Text(message, style: Theme.of(context).textTheme.bodyLarge),
        ],
      ),
    );
  }
}

/// A one-line note in the muted style, for caveats under a section.
class Caveat extends StatelessWidget {
  const Caveat({super.key, required this.text, this.icon = Icons.info_outline});

  final String text;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    final ColorScheme scheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.only(top: 4, bottom: 12),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Icon(icon, size: 15, color: scheme.onSurfaceVariant),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              text,
              style: Theme.of(context)
                  .textTheme
                  .bodyMedium
                  ?.copyWith(fontSize: 12),
            ),
          ),
        ],
      ),
    );
  }
}

/// Show a snack bar, guarding against a disposed context.
void showTrueMedSnack(BuildContext context, String message,
    {String? severity}) {
  final ScaffoldMessengerState? messenger = ScaffoldMessenger.maybeOf(context);
  if (messenger == null) return;
  final SeverityColors colors = severityColorsOf(context);
  messenger.hideCurrentSnackBar();
  messenger.showSnackBar(
    SnackBar(
      content: Text(
        message,
        style: severity == null
            ? null
            : TextStyle(color: colors.onContainerFor(severity)),
      ),
      backgroundColor:
          severity == null ? null : colors.containerFor(severity),
      duration: const Duration(seconds: 4),
    ),
  );
}

/// A yes/no dialog. Returns false if dismissed.
///
/// [destructive] is passed by the recall and clear-history flows. The confirming
/// button is coloured, and it is deliberately *not* the default focused action:
/// nothing in this app should be confirmable by reflex.
Future<bool> confirm(
  BuildContext context, {
  required String title,
  required String body,
  required String confirmLabel,
  bool destructive = false,
}) async {
  final Strings s = Strings.of(context);
  final ColorScheme scheme = Theme.of(context).colorScheme;
  final bool? answer = await showDialog<bool>(
    context: context,
    builder: (BuildContext context) => AlertDialog(
      title: Text(title),
      content: Text(body),
      actions: <Widget>[
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: Text(s.cancel),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(true),
          style: destructive
              ? FilledButton.styleFrom(
                  backgroundColor: scheme.error,
                  foregroundColor: scheme.onError,
                )
              : null,
          child: Text(confirmLabel),
        ),
      ],
    ),
  );
  return answer ?? false;
}
