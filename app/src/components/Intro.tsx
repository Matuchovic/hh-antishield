import { useEffect, useRef, useState } from "react";
import brandLogo from "../assets/hh-antishield-logo.png";
import { playIntro } from "../lib/sound";
import { Core } from "./Emblem";

// Úvodní znělka: jádro se nabije, prstence se rozvinou, zazní akord a objeví
// se logo. Kliknutím nebo klávesou jde přeskočit. Trvá asi 3 s.

const SHOW_MS = 2700;
const LEAVE_MS = 650;

export function Intro({ sound, onDone }: { sound: boolean; onDone: () => void }) {
  const [leaving, setLeaving] = useState(false);
  const done = useRef(false);

  const finish = () => {
    if (done.current) return;
    done.current = true;
    setLeaving(true);
    window.setTimeout(onDone, LEAVE_MS);
  };

  useEffect(() => {
    if (sound) playIntro();
    const timer = window.setTimeout(finish, SHOW_MS);
    const onKey = () => finish();
    window.addEventListener("keydown", onKey);
    return () => {
      window.clearTimeout(timer);
      window.removeEventListener("keydown", onKey);
    };
    // Spustí se jednou při startu aplikace.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className={`intro${leaving ? " is-leaving" : ""}`} onClick={finish} role="presentation">
      <div className="intro-rays" />
      <div className="intro-ring r1" />
      <div className="intro-ring r2" />
      <div className="intro-ring r3" />
      <div className="intro-core">
        <Core />
      </div>
      <div className="intro-flash" />
      <div className="intro-brand">
        <img src={brandLogo} alt="H&H AntiShield – Antivirus & System Protection" draggable={false} />
        <span className="logo-shine" />
      </div>
      <p className="intro-skip">Kliknutím přeskočíte</p>
    </div>
  );
}
