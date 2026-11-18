import type { Metadata } from "next";
import { Inter, JetBrains_Mono, Space_Grotesk } from "next/font/google";
import Link from "next/link";
import { Mark } from "@/components/Mark";
import { currentSession, oidc } from "@/lib/session";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });
const grotesk = Space_Grotesk({ subsets: ["latin"], variable: "--font-space-grotesk" });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-jetbrains-mono" });

export const metadata: Metadata = {
  title: "PRAXIS",
  description: "Detection coverage across every client",
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const session = await currentSession();
  return (
    <html lang="en" className={`${inter.variable} ${grotesk.variable} ${mono.variable}`}>
      <body className="min-h-screen font-sans antialiased">
        <header className="border-b border-line">
          <div className="mx-auto flex max-w-7xl items-center gap-3 px-4 py-3 sm:px-6">
            <Link href="/" className="flex items-center gap-3">
              <Mark />
              <span className="font-display text-lg font-semibold tracking-[0.2em] text-fog">
                PRAXIS
              </span>
            </Link>
            <nav className="ml-auto flex gap-5 text-sm text-mute">
              <Link href="/" className="hover:text-fog">
                Fleet
              </Link>
              <Link href="/packs" className="hover:text-fog">
                Rule packs
              </Link>
              <Link href="/hunts" className="hover:text-fog">
                Hunts
              </Link>
              <Link href="/audit" className="hover:text-fog">
                Audit
              </Link>
              <Link href="/settings" className="hover:text-fog">
                Settings
              </Link>
              {session && oidc.enabled ? (
                <form action="/logout" method="post" className="flex items-center gap-2">
                  <span className="text-fog">{session.name}</span>
                  <button className="text-mute hover:text-fog">Sign out</button>
                </form>
              ) : null}
            </nav>
          </div>
        </header>
        <main className="mx-auto max-w-7xl px-4 py-6 sm:px-6">{children}</main>
      </body>
    </html>
  );
}
