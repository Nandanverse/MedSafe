/// Every user-facing string in the app.
///
/// # Why this is hand-written and not `flutter gen-l10n`
///
/// The generated approach — `.arb` files, `l10n.yaml`, `AppLocalizations` — is the
/// usual choice and is better for an app with a translation team and a dozen
/// locales. It is the wrong choice here for two reasons. The generated class is not
/// committed, so a fresh clone does not analyse until a build step has run, and
/// every string is a lookup by name that no tool checks: a typo in an `.arb` key
/// surfaces as a missing translation at runtime. A plain abstract class gets both
/// properties for free — the compiler refuses to build a locale that has not
/// implemented every string, and there is nothing to generate.
///
/// # Adding Hindi
///
/// Subclass [Strings], override every member (the compiler enumerates them for
/// you), add the locale to [StringsDelegate.supported], and add
/// `GlobalMaterialLocalizations.delegate` — already wired in `main.dart` — does the
/// rest for Material's own strings. No other file changes. The app currently ships
/// English only, deliberately: a half-translated medical warning is more dangerous
/// than an untranslated one, because a patient who reads the Hindi headline and not
/// the English detail gets half the message.
///
/// # The rule these strings follow
///
/// Every verdict has three parts: what it is, why, and **what to do**. The third is
/// the one that gets left out, and it is the only one that changes an outcome. A
/// patient told "COUNTERFEIT" and nothing else has learned that something is wrong;
/// a patient told "do not take this, return it to the pharmacy, report it here" can
/// act. Note also that UNVERIFIABLE's wording works hard not to imply the medicine
/// is fake — that verdict means the *app* failed, and saying so plainly is the
/// difference between a trustworthy tool and one that cries wolf.
library;

import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../core/rules.dart';

/// The string table. One implementation per locale.
abstract class Strings {
  const Strings();

  /// Read the strings for the current locale.
  ///
  /// Falls back to English rather than throwing when no delegate is installed, so
  /// that a widget test which pumps a bare `MaterialApp` still renders text instead
  /// of crashing on a null.
  static Strings of(BuildContext context) =>
      Localizations.of<Strings>(context, Strings) ?? const StringsEn();

  String get locale;

  // ── App and navigation ───────────────────────────────────────────────────
  String get appName;
  String get tagline;
  String get scanTab;
  String get historyTab;
  String get moreTab;
  String get back;
  String get cancel;
  String get close;
  String get retry;
  String get done;
  String get saveAction;
  String get signIn;
  String get signOut;
  String get settings;
  String get diagnostics;

  // ── Development-build warning ────────────────────────────────────────────
  String get devBuildTitle;
  String get devBuildBody;
  String get insecureTransportTitle;
  String get insecureTransportBody;

  // ── Scanning ─────────────────────────────────────────────────────────────
  String get scanTitle;
  String get scanPrompt;
  String get scanHint;
  String get cameraPermissionTitle;
  String get cameraPermissionBody;
  String get openSettings;
  String get torchOn;
  String get torchOff;
  String get enterCodeManually;
  String get productIdLabel;
  String get productIdHint;
  String get checkAction;
  String get scanningAgain;

  // ── Verdicts ─────────────────────────────────────────────────────────────
  /// Two to four words. The largest text on the screen.
  String verdictHeadline(String verdict);

  /// One or two sentences explaining the verdict.
  String verdictExplanation(String verdict);

  /// The action to take. Never empty, even for GENUINE.
  String verdictAction(String verdict);

  String get verifiedOnline;
  String get verifiedOfflineOnly;
  String get servedFromCache;
  String cachedAgo(String duration);
  String get whyThisResult;
  String get checksTitle;
  String checkLabel(String check);
  String checkOutcome(String outcome);

  // ── Medicine details ─────────────────────────────────────────────────────
  String get medicineDetails;
  String get genericNameLabel;
  String get brandNameLabel;
  String get manufacturerLabel;
  String get licenceLabel;
  String get batchLabel;
  String get manufacturedLabel;
  String get expiryLabel;
  String get quantityLabel;
  String get excipientsLabel;
  String get typeLabel;
  String get statusLabel;
  String get locationLabel;
  String expiresIn(int days);
  String expiredDaysAgo(int days);

  // ── Custody trail ────────────────────────────────────────────────────────
  String get custodyTitle;
  String get custodyEmpty;
  String get custodyOfflineNote;

  // ── Cold chain ───────────────────────────────────────────────────────────
  String get coldChainTitle;
  String get coldChainNotApplicable;
  String get coldChainUnmonitored;
  String coldChainOk(String range, int readings);
  String coldChainBreached(int excursions, String worst);
  String get coldChainWhyItMatters;
  String get temperatureRangeLabel;
  String get readingsLabel;
  String get lastReadingLabel;

  // ── Reporting ────────────────────────────────────────────────────────────
  String get reportTitle;
  String get reportIntro;
  String get reportAnonymousNote;
  String get pharmacyNameLabel;
  String get districtLabel;
  String get stateLabel;
  String get notesLabel;
  String get notesHint;
  String get contactLabel;
  String get contactHint;
  String get attachPhoto;
  String get retakePhoto;
  String get removePhoto;
  String get includeLocation;
  String get includeLocationNote;
  String get submitReport;
  String get reportSent;
  String reportSentWithId(String id);
  String get reportSentBody;
  String get reportAlreadyFiled;
  String get requiredField;

  // ── History ──────────────────────────────────────────────────────────────
  String get historyTitle;
  String get historyEmpty;
  String get historyEmptyHint;
  String get clearHistory;
  String get clearHistoryConfirm;
  String get clearHistoryBody;
  String historyCount(int total, int concerning);
  String get reportedChip;

  // ── Sign in ──────────────────────────────────────────────────────────────
  String get signInTitle;
  String get signInIntro;
  String get apiKeyLabel;
  String get apiKeyHint;
  String get signedInAs;
  String get signOutConfirm;
  String get signOutBody;

  // ── Pharmacy ─────────────────────────────────────────────────────────────
  String get pharmacyTitle;
  String get acceptStockTitle;
  String get acceptStockIntro;
  String get dispenseTitle;
  String get dispenseIntro;
  String get locationCodeLabel;
  String get locationCodeHint;
  String get markReceived;
  String get markDispensed;
  String recordedAt(String status, String location);
  String get recordedBlockedTitle;

  // ── Regulator ────────────────────────────────────────────────────────────
  String get regulatorTitle;
  String get recallTitle;
  String get recallIntro;
  String get batchNoLabel;
  String get reasonLabel;
  String get reasonHint;
  String get startRecall;
  String get recallConfirmTitle;
  String recallConfirmBody(String batch);
  String recallProgress(int done, int calls);
  String recallComplete(int recalled, int already);
  String recallIncomplete(int recalled);
  String get recallIncompleteWarning;

  // ── Dashboards ───────────────────────────────────────────────────────────
  String get cdscoDashboardTitle;
  String get pharmaDashboardTitle;
  String get windowLabel;
  String windowDays(int days);
  String get reportsMetric;
  String get openReportsMetric;
  String get unitsRecalledMetric;
  String get breachesMetric;
  String get clonesMetric;
  String get unitsMintedMetric;
  String get unitsDispensedMetric;
  String get batchesMetric;
  String get districtsTitle;
  String get alertsTitle;
  String get alertsEmpty;
  String alertKindLabel(String kind);
  String get batchesTitle;
  String get expiringSoonTitle;
  String get truncatedNote;

  // ── Errors and empty states ──────────────────────────────────────────────
  String get offlineTitle;
  String get offlineBody;
  String get somethingWentWrong;
  String get noKeyListTitle;
  String get noKeyListBody;
  String get trustKeysUpdated;
  String get updateKeyList;
  String get resetToBuiltIn;
  String get resetToBuiltInBody;
  String keyListSummary(int keys, String issued);

  // ── Added while building the screens ─────────────────────────────────────
  //
  // Kept as one block rather than filed into the sections above, for the
  // translator's benefit: this is the delta a Hindi implementation has to cover
  // beyond the table as it stood when the screens did not exist yet. Grouped by
  // the screen that reads them.

  // Scan
  String get checkingNow;
  String get cameraUnavailable;
  String get offlineChip;

  // Verdict and details
  String get viewDetails;
  String get warningsTitle;
  String medTypeLabel(String type);

  // Temperature history
  String get observedRangeLabel;
  String get noReadings;
  String coldChainOutsideRange(String worst);

  // Report
  String get takePhoto;
  String get chooseFromGallery;
  String get photoTooLarge;
  String get reportingLabel;

  // History
  String get checkAgain;
  String get offlineOnlyChip;

  // Sign in
  String get signedInOk;

  // Pharmacy
  String get recordAnother;

  // Dashboards
  String get unitsRemainingLabel;
  String get statusCountsTitle;
  String get refreshAction;

  // More
  String get staffToolsTitle;
  String get aboutTitle;
  String get keyListTitle;
  String trustSourceLabel(String source);
  String get copyDiagnostics;

  // ── Formatting ───────────────────────────────────────────────────────────
  /// `04 Jun 2026`. Day-first, because that is how dates are written in India and
  /// a US-style `06/04/2026` on an expiry date is genuinely ambiguous.
  String formatDate(DateTime when);

  /// `04 Jun 2026, 09:12`.
  String formatDateTime(DateTime when);

  /// A coarse relative time: `2 hours ago`.
  String relativeTime(Duration ago);
}

class StringsEn extends Strings {
  const StringsEn();

  @override
  String get locale => 'en';

  @override
  String get appName => 'TrueMed';
  @override
  String get tagline => 'Truth in every medicine';
  @override
  String get scanTab => 'Scan';
  @override
  String get historyTab => 'History';
  @override
  String get moreTab => 'More';
  @override
  String get back => 'Back';
  @override
  String get cancel => 'Cancel';
  @override
  String get close => 'Close';
  @override
  String get retry => 'Try again';
  @override
  String get done => 'Done';
  @override
  String get saveAction => 'Save';
  @override
  String get signIn => 'Sign in';
  @override
  String get signOut => 'Sign out';
  @override
  String get settings => 'Settings';
  @override
  String get diagnostics => 'Diagnostics';

  @override
  String get devBuildTitle => 'Development build — not for clinical use';
  @override
  String get devBuildBody =>
      'This app is pinned to a test signing key whose private half is published in '
      'the TrueMed source code. Anyone can produce codes that verify as genuine '
      'here. Do not use these results to make a decision about real medicine.';
  @override
  String get insecureTransportTitle => 'Unencrypted connection';
  @override
  String get insecureTransportBody =>
      'This build talks to the TrueMed server over plain HTTP. Signature checking '
      'is unaffected, but anyone on this network can see which medicines you scan.';

  @override
  String get scanTitle => 'Scan a medicine';
  @override
  String get scanPrompt => 'Point the camera at the QR code on the strip or vial';
  @override
  String get scanHint =>
      'Hold the phone about 15 cm away. The code does not have to fill the frame.';
  @override
  String get cameraPermissionTitle => 'Camera access needed';
  @override
  String get cameraPermissionBody =>
      'TrueMed reads the QR code with the camera. Nothing is recorded and no image '
      'leaves your phone unless you attach a photo to a report yourself.';
  @override
  String get openSettings => 'Open settings';
  @override
  String get torchOn => 'Turn on torch';
  @override
  String get torchOff => 'Turn off torch';
  @override
  String get enterCodeManually => 'Enter the code by hand';
  @override
  String get productIdLabel => 'Product ID';
  @override
  String get productIdHint => 'PARACETAMOL500MG_PARACIP500_2026_000001';
  @override
  String get checkAction => 'Check';
  @override
  String get scanningAgain => 'Scan another';

  @override
  String verdictHeadline(String verdict) => switch (verdict) {
        Verdict.genuine => 'Genuine',
        Verdict.offlineOk => 'Signature valid, not yet confirmed',
        Verdict.expired => 'Expired',
        Verdict.coldChain => 'Cold chain broken',
        Verdict.clone => 'Possible duplicate',
        Verdict.recalled => 'Recalled',
        Verdict.counterfeit => 'Counterfeit',
        Verdict.unverifiable => 'Could not check',
        _ => 'Unknown result',
      };

  @override
  String verdictExplanation(String verdict) => switch (verdict) {
        Verdict.genuine =>
          "The manufacturer's digital signature on this code is valid, and the "
              'TrueMed record matches it. This medicine is what the packet says it '
              'is.',
        Verdict.offlineOk =>
          "The manufacturer's signature is valid — this phone checked it without "
              'needing the internet. What could not be checked is whether the batch '
              'has since been recalled, or whether this same code has been scanned '
              'somewhere else.',
        Verdict.expired =>
          'The signature is valid, so the medicine is genuine, but it is past the '
          'expiry date printed by the manufacturer. Medicines lose strength after '
          'that date, and some break down into compounds that are not safe.',
        Verdict.coldChain =>
          'This vaccine went outside its safe temperature range while it was being '
          'transported or stored. A vaccine that has been too warm may no longer '
          'work at all, and it will look and feel completely normal.',
        Verdict.clone =>
          'This exact code has been scanned far more times, or in far more places, '
          'than one strip of medicine should be. That is the signature of a real '
          'code photographed and reprinted onto counterfeit packets.',
        Verdict.recalled =>
          'The manufacturer or CDSCO has withdrawn this batch. That usually means a '
          'problem was found after it was distributed — contamination, a wrong dose, '
          'or a failed quality test.',
        Verdict.counterfeit =>
          'The digital signature on this code is not valid. This medicine did not '
          'come from the manufacturer named on it. It may contain the wrong drug, '
          'the wrong amount, or nothing at all.',
        Verdict.unverifiable =>
          'TrueMed could not complete the check. This is a problem on this phone or '
          'with the network — most often an out-of-date list of manufacturer keys. '
          'It is not evidence that the medicine is fake.',
        _ =>
          'This version of TrueMed does not recognise the result the server sent. '
              'Update the app.',
      };

  @override
  String verdictAction(String verdict) => switch (verdict) {
        Verdict.genuine => 'Take it as your doctor or pharmacist directed.',
        Verdict.offlineOk =>
          'Check again once you have internet, especially before giving this to a '
              'child or taking it long-term.',
        Verdict.expired =>
          'Do not take it. Return it to the pharmacy — an expired strip on sale is '
              'worth reporting.',
        Verdict.coldChain =>
          'Do not let this be administered. Tell the health worker or pharmacist '
              'and report it here.',
        Verdict.clone => 'Do not take it. Report it, and keep the packet.',
        Verdict.recalled =>
          'Do not take it. Return it to the pharmacy and ask for a replacement '
              'from a different batch.',
        Verdict.counterfeit =>
          'Do not take it. Report it now and keep the packet — it is the evidence.',
        Verdict.unverifiable =>
          'Try again with internet. Do not assume the medicine is fake, and do not '
              'assume it is fine either.',
        _ => 'Update TrueMed and scan again.',
      };

  @override
  String get verifiedOnline => 'Checked against the TrueMed server';
  @override
  String get verifiedOfflineOnly => 'Checked on this phone only';
  @override
  String get servedFromCache => 'From a recent server answer';
  @override
  String cachedAgo(String duration) => 'Server answer from $duration ago';
  @override
  String get whyThisResult => 'Why this result?';
  @override
  String get checksTitle => 'What was checked';
  // The wording here is deliberately longer than `CheckName.label` in
  // lib/core/rules.dart. That one exists for diagnostics and test output, where
  // "Digital signature" is the right length; this one is read by a patient who has
  // tapped "why this result?" and needs to know what was actually established. The
  // fallback delegates to the core so an unrecognised check name from a newer server
  // still renders as something, and only one place has to know how to degrade.
  @override
  String checkLabel(String check) => switch (check) {
        CheckName.structure => 'The code is a well-formed TrueMed code',
        CheckName.signature => "The manufacturer's digital signature",
        CheckName.expiry => 'Still within its expiry date',
        CheckName.onChain => 'A matching record on the TrueMed ledger',
        CheckName.coldChain => 'Kept at a safe temperature throughout',
        CheckName.cloneTelemetry => 'Not scanned like a duplicated code',
        _ => CheckName.label(check),
      };

  @override
  String checkOutcome(String outcome) => switch (outcome) {
        Check.pass => 'Passed',
        Check.fail => 'Failed',
        // "No internet", not "offline" — the distinction the user cares about is
        // that the check was *not performed*, and naming the reason is what stops
        // a skipped recall check reading as a passed one.
        Check.skippedOffline => 'Not checked — no internet',
        Check.skippedNoPayload => 'Not checked — code was typed by hand',
        Check.notApplicable => 'Does not apply to this product',
        Check.notEvaluated => 'Not checked',
        _ => outcome,
      };

  @override
  String get medicineDetails => 'Medicine details';
  @override
  String get genericNameLabel => 'Generic name';
  @override
  String get brandNameLabel => 'Brand';
  @override
  String get manufacturerLabel => 'Manufacturer';
  @override
  String get licenceLabel => 'Licence no.';
  @override
  String get batchLabel => 'Batch';
  @override
  String get manufacturedLabel => 'Manufactured';
  @override
  String get expiryLabel => 'Expires';
  @override
  String get quantityLabel => 'Quantity';
  @override
  String get excipientsLabel => 'Other ingredients';
  @override
  String get typeLabel => 'Type';
  @override
  String get statusLabel => 'Status';
  @override
  String get locationLabel => 'Last seen at';
  @override
  String expiresIn(int days) => days == 0
      ? 'Expires today'
      : days == 1
          ? 'Expires tomorrow'
          : 'Expires in $days days';
  @override
  String expiredDaysAgo(int days) => days == 1
      ? 'Expired yesterday'
      : 'Expired $days days ago';

  @override
  String get custodyTitle => 'Where this has been';
  @override
  String get custodyEmpty => 'No movement recorded yet.';
  @override
  String get custodyOfflineNote =>
      'The full trail needs internet — it lives on the ledger, not on the strip.';

  @override
  String get coldChainTitle => 'Temperature history';
  @override
  String get coldChainNotApplicable =>
      'This medicine does not need refrigeration, so no temperature is tracked.';
  @override
  String get coldChainUnmonitored =>
      'This product needs refrigeration, but no sensor readings have been recorded '
      'for it. That is not a pass — it means nobody was watching.';
  @override
  String coldChainOk(String range, int readings) =>
      '$readings readings, all within $range.';
  @override
  String coldChainBreached(int excursions, String worst) => excursions == 1
      ? 'One reading outside the safe range, worst $worst.'
      : '$excursions readings outside the safe range, worst $worst.';
  @override
  String get coldChainWhyItMatters =>
      'Vaccines are grown from living material. Too warm and the active part breaks '
      'down; too cold and the liquid can freeze and crack the vial. Either way the '
      'vaccine can look perfect and give no protection at all.';
  @override
  String get temperatureRangeLabel => 'Safe range';
  @override
  String get readingsLabel => 'Readings';
  @override
  String get lastReadingLabel => 'Last reading';

  @override
  String get reportTitle => 'Report this medicine';
  @override
  String get reportIntro =>
      'Your report goes to CDSCO with the scanned code attached. Reports are how '
      'counterfeit batches get found — a single one from the right pharmacy has '
      'started a recall.';
  @override
  String get reportAnonymousNote =>
      'You do not have to give your name or number. TrueMed does not attach your '
      'identity to a report unless you type it in below.';
  @override
  String get pharmacyNameLabel => 'Where did you get it?';
  @override
  String get districtLabel => 'District';
  @override
  String get stateLabel => 'State';
  @override
  String get notesLabel => 'Anything else? (optional)';
  @override
  String get notesHint =>
      'Loose tablets, smudged printing, an unusual smell, a price far below normal…';
  @override
  String get contactLabel => 'Your phone or email (optional)';
  @override
  String get contactHint => 'Only if you want an investigator to be able to ask';
  @override
  String get attachPhoto => 'Add a photo of the packet';
  @override
  String get retakePhoto => 'Take a different photo';
  @override
  String get removePhoto => 'Remove photo';
  @override
  String get includeLocation => 'Include my location';
  @override
  String get includeLocationNote =>
      'Helps CDSCO see where a fake batch is being sold.';
  @override
  String get submitReport => 'Send report';
  @override
  String get reportSent => 'Report sent';
  @override
  String reportSentWithId(String id) => 'Report sent — reference $id';
  @override
  String get reportSentBody =>
      'Keep the packet. If an investigator follows this up, the physical strip is '
      'the evidence that matters most.';
  @override
  String get reportAlreadyFiled => 'You have already reported this code.';
  @override
  String get requiredField => 'Please fill this in';

  @override
  String get historyTitle => 'Your scans';
  @override
  String get historyEmpty => 'Nothing scanned yet';
  @override
  String get historyEmptyHint =>
      'Scans you make are kept on this phone, encrypted, and never uploaded.';
  @override
  String get clearHistory => 'Delete all scans';
  @override
  String get clearHistoryConfirm => 'Delete your scan history?';
  @override
  String get clearHistoryBody =>
      'This removes every scan from this phone permanently. Reports you have already '
      'sent are not affected.';
  @override
  String historyCount(int total, int concerning) => concerning == 0
      ? '$total scans, none concerning'
      : '$total scans, $concerning needing attention';
  @override
  String get reportedChip => 'Reported';

  @override
  String get signInTitle => 'Sign in';
  @override
  String get signInIntro =>
      'Patients do not need to sign in — scanning works without it. A key is only '
      'needed to record stock movements, issue recalls, or see a dashboard.';
  @override
  String get apiKeyLabel => 'API key';
  @override
  String get apiKeyHint => 'tm_pharmacy_…';
  @override
  String get signedInAs => 'Signed in as';
  @override
  String get signOutConfirm => 'Sign out?';
  @override
  String get signOutBody =>
      'The key is removed from this phone. Scanning still works.';

  @override
  String get pharmacyTitle => 'Pharmacy';
  @override
  String get acceptStockTitle => 'Receive stock';
  @override
  String get acceptStockIntro =>
      'Scan each strip as it arrives. This records it as being at your pharmacy, so '
      'a patient scanning it later sees a complete chain from the factory.';
  @override
  String get dispenseTitle => 'Dispense';
  @override
  String get dispenseIntro =>
      'Scan as you hand medicine over. This closes the chain and is what makes a '
      'reprinted duplicate of this code detectable.';
  @override
  String get locationCodeLabel => 'Your pharmacy code';
  @override
  String get locationCodeHint => 'PHARM_MUM_0142';
  @override
  String get markReceived => 'Record as received';
  @override
  String get markDispensed => 'Record as dispensed';
  @override
  String recordedAt(String status, String location) =>
      'Recorded as $status at $location';
  @override
  String get recordedBlockedTitle => 'Cannot record this move';

  @override
  String get regulatorTitle => 'CDSCO';
  @override
  String get recallTitle => 'Recall a batch';
  @override
  String get recallIntro =>
      'Every unit in the batch is marked recalled on the ledger. Anyone scanning one '
      'afterwards sees a red warning with your reason on it. This cannot be undone.';
  @override
  String get batchNoLabel => 'Batch number';
  @override
  String get reasonLabel => 'Reason';
  @override
  String get reasonHint => 'Shown to every pharmacist and patient who scans a unit';
  @override
  String get startRecall => 'Recall this batch';
  @override
  String get recallConfirmTitle => 'Recall this batch?';
  @override
  String recallConfirmBody(String batch) =>
      'Batch $batch will be marked recalled for everyone, immediately and '
      'permanently. There is no undo.';
  @override
  String recallProgress(int done, int calls) =>
      '$done units recalled so far ($calls transactions)';
  @override
  String recallComplete(int recalled, int already) => already == 0
      ? 'Recall complete — $recalled units'
      : 'Recall complete — $recalled units, $already were already recalled';
  @override
  String recallIncomplete(int recalled) =>
      'Stopped after $recalled units — the batch is only partly recalled';
  @override
  String get recallIncompleteWarning =>
      'Units that were not reached are still valid on the ledger and will scan as '
      'genuine. Run the recall again, on a better connection, until it completes.';

  @override
  String get cdscoDashboardTitle => 'National overview';
  @override
  String get pharmaDashboardTitle => 'Your batches';
  @override
  String get windowLabel => 'Period';
  @override
  String windowDays(int days) => days == 1 ? 'Last 24 hours' : 'Last $days days';
  @override
  String get reportsMetric => 'Reports';
  @override
  String get openReportsMetric => 'Still open';
  @override
  String get unitsRecalledMetric => 'Units recalled';
  @override
  String get breachesMetric => 'Cold chain breaches';
  @override
  String get clonesMetric => 'Suspected duplicates';
  @override
  String get unitsMintedMetric => 'Units made';
  @override
  String get unitsDispensedMetric => 'Units dispensed';
  @override
  String get batchesMetric => 'Batches';
  @override
  String get districtsTitle => 'By district';
  @override
  String get alertsTitle => 'Needs attention';
  @override
  String get alertsEmpty => 'Nothing flagged in this period.';
  @override
  String alertKindLabel(String kind) => switch (kind) {
        'counterfeit_report' => 'Counterfeit reported',
        'clone_suspected' => 'Duplicate code suspected',
        'cold_chain_breach' => 'Cold chain breach',
        'recall_incomplete' => 'Recall left unfinished',
        // An unrecognised kind is shown, not hidden. §4.4a requires it: a newer
        // server flagging a new class of problem must not go unnoticed because an
        // older app had no label for it.
        _ => kind.replaceAll('_', ' '),
      };
  @override
  String get batchesTitle => 'Batches';
  @override
  String get expiringSoonTitle => 'Expiring within 90 days';
  @override
  String get truncatedNote =>
      'Showing the most significant rows only — there are more.';

  @override
  String get offlineTitle => 'No internet';
  @override
  String get offlineBody =>
      'Signature checking still works. Recalls, duplicate detection and temperature '
      'history need a connection.';
  @override
  String get somethingWentWrong => 'Something went wrong';
  @override
  String get noKeyListTitle => 'No manufacturer key list';
  @override
  String get noKeyListBody =>
      'TrueMed cannot check signatures without the list of manufacturer keys. '
      'Connect to the internet once to download it.';
  @override
  String get trustKeysUpdated => 'Manufacturer key list updated';
  @override
  String get updateKeyList => 'Update key list now';
  @override
  String get resetToBuiltIn => 'Reset to the built-in key list';
  @override
  String get resetToBuiltInBody =>
      'Clears the downloaded list and the rollback record, then reloads the list '
      'shipped with the app. Use this only if scanning has stopped working after a '
      'bad update.';
  @override
  String keyListSummary(int keys, String issued) =>
      '$keys manufacturer keys, issued $issued';

  @override
  String formatDate(DateTime when) => DateFormat('dd MMM yyyy').format(when);

  @override
  String formatDateTime(DateTime when) =>
      DateFormat('dd MMM yyyy, HH:mm').format(when);

  @override
  String relativeTime(Duration ago) {
    if (ago.inSeconds < 60) return 'just now';
    if (ago.inMinutes < 60) {
      return ago.inMinutes == 1 ? '1 minute' : '${ago.inMinutes} minutes';
    }
    if (ago.inHours < 24) {
      return ago.inHours == 1 ? '1 hour' : '${ago.inHours} hours';
    }
    return ago.inDays == 1 ? '1 day' : '${ago.inDays} days';
  }
}

/// Installs [Strings] into the widget tree.
class StringsDelegate extends LocalizationsDelegate<Strings> {
  const StringsDelegate();

  /// Locales the app ships strings for.
  ///
  /// Add `Locale('hi')` here alongside a `StringsHi` implementation and the app
  /// picks it up from the device locale automatically.
  static const List<Locale> supported = <Locale>[Locale('en')];

  @override
  bool isSupported(Locale locale) =>
      supported.any((Locale l) => l.languageCode == locale.languageCode);

  @override
  Future<Strings> load(Locale locale) async => switch (locale.languageCode) {
        _ => const StringsEn(),
      };

  @override
  bool shouldReload(StringsDelegate old) => false;
}
