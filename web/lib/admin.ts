import { notFound } from "next/navigation";
import { ADMIN_ROLE, currentSession } from "@/lib/session";

// Pages that span every client (packs, hunts, audit, settings) are for administrators.
export async function requireAdmin(): Promise<void> {
  const session = await currentSession();
  if (!session?.roles.includes(ADMIN_ROLE)) notFound();
}

export async function isAdmin(): Promise<boolean> {
  return Boolean((await currentSession())?.roles.includes(ADMIN_ROLE));
}
