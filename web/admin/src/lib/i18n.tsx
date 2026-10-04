import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import { getStoredLocale, LANGUAGE_STORAGE_KEY, translate, type LocaleCode, isLocaleCode } from "../locales";

type I18nValue = {
  locale: LocaleCode;
  setLocale: (code: string) => void;
  t: (key: string) => string;
};

const I18nContext = createContext<I18nValue | null>(null);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<LocaleCode>(getStoredLocale);
  const value = useMemo<I18nValue>(
    () => ({
      locale,
      setLocale: (code: string) => {
        if (!isLocaleCode(code)) return;
        localStorage.setItem(LANGUAGE_STORAGE_KEY, code);
        setLocaleState(code);
        document.documentElement.lang = code;
      },
      t: (key: string) => translate(locale, key)
    }),
    [locale]
  );
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n() {
  const value = useContext(I18nContext);
  if (!value) throw new Error("i18n missing");
  return value;
}
