import en from "./en.json";
import deOverrides from "./de.json";

/** localStorage key for the active UI language. Adding a language is a JSON file plus one entry here. */
export const LANGUAGE_STORAGE_KEY = "mail-warden.i18n.language";

export const DEFAULT_LOCALE = "en" as const;

const de = { ...en, ...deOverrides };

const LOCALES = [
  { code: "en", label: "English", nativeLabel: "English", translation: en },
  { code: "de", label: "German", nativeLabel: "Deutsch", translation: de }
] as const;

export const SUPPORTED_LOCALES = LOCALES.map(({ code, label, nativeLabel }) => ({
  code,
  label,
  nativeLabel
}));

export type LocaleCode = (typeof LOCALES)[number]["code"];
export type TranslationKey = keyof typeof en;

const bundles: Record<string, Record<string, string>> = Object.fromEntries(
  LOCALES.map((locale) => [locale.code, locale.translation])
);

export function isLocaleCode(value: string): value is LocaleCode {
  return LOCALES.some((locale) => locale.code === value);
}

export function getStoredLocale(): LocaleCode {
  try {
    const raw = localStorage.getItem(LANGUAGE_STORAGE_KEY) ?? "";
    if (isLocaleCode(raw)) return raw;
  } catch {
    /* ignore private mode */
  }
  return DEFAULT_LOCALE;
}

export function translate(locale: string, key: string, vars?: Record<string, string | number>): string {
  let text = bundles[locale]?.[key] ?? bundles[DEFAULT_LOCALE]?.[key] ?? key;
  if (vars) {
    for (const [name, value] of Object.entries(vars)) text = text.replaceAll(`{{${name}}}`, String(value));
  }
  return text;
}
