import { Panel } from "@/components/Stat";
import { api } from "@/lib/api";

export const dynamic = "force-dynamic";

type Status = {
  chatgpt: {
    connected: boolean;
    plan_usage: boolean;
    account: { email: string | null; name: string | null } | null;
    model: string | null;
    models: { slug: string; name: string }[];
    models_error?: string;
  };
};

const button = "rounded-md border border-brass px-3 py-1.5 text-sm text-brass hover:bg-brass hover:text-obsidian";

export default async function Settings({ searchParams }: { searchParams: Promise<{ error?: string; connected?: string }> }) {
  const { error, connected } = await searchParams;
  const status = await api<Status>("/api/llm?models=true");
  const chatgpt = status?.chatgpt;
  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-display text-2xl font-semibold">Settings</h1>
        <p className="text-sm text-mute">How the agents reach a model.</p>
      </div>
      {error ? (
        <div className="rounded-lg border border-ember bg-slate px-4 py-3 text-sm text-ember">{error}</div>
      ) : null}
      {connected && chatgpt?.plan_usage ? (
        <div className="rounded-lg border border-teal bg-slate px-4 py-3 text-sm text-teal">
          Signed in. The agents will use your ChatGPT plan.
        </div>
      ) : null}
      <Panel title="ChatGPT plan" note="Sign in with ChatGPT so your plan pays for the agents' model calls.">
        {chatgpt?.connected ? (
          <div className="space-y-4 text-sm">
            <p>
              Signed in as <span className="font-medium text-fog">{chatgpt.account?.email ?? chatgpt.account?.name ?? "your ChatGPT account"}</span>.
            </p>
            {chatgpt.plan_usage ? (
              <form action="/auth/model" method="post" className="flex flex-wrap items-end gap-3">
                <label className="block">
                  <span className="text-xs text-mute">Model for the agents</span>
                  <select
                    name="model"
                    defaultValue={chatgpt.model ?? chatgpt.models[0]?.slug}
                    className="block rounded border border-line bg-obsidian px-2 py-1.5 text-sm text-fog"
                  >
                    {chatgpt.models.map((m) => (
                      <option key={m.slug} value={m.slug}>
                        {m.name}
                      </option>
                    ))}
                  </select>
                </label>
                <button className={button}>Save</button>
                {chatgpt.models_error ? <span className="text-xs text-ember">{chatgpt.models_error}</span> : null}
              </form>
            ) : (
              <p className="text-ember">
                Plan usage was not granted, so the agents cannot use this sign-in. Sign in again and allow
                PRAXIS to use your plan.
              </p>
            )}
            <div className="flex flex-wrap gap-3">
              {!chatgpt.plan_usage ? (
                <form action="/auth/start" method="post">
                  <button className={button}>Sign in with ChatGPT</button>
                </form>
              ) : null}
              <form action="/auth/disconnect" method="post">
                <button className="rounded-md border border-line px-3 py-1.5 text-sm text-mute hover:text-fog">
                  Sign out of ChatGPT
                </button>
              </form>
            </div>
            <p className="text-xs text-mute">
              Usage counts against your ChatGPT plan; see{" "}
              <a className="text-brass hover:underline" href="https://chatgpt.com/settings/usage">
                chatgpt.com/settings/usage
              </a>
              . PRAXIS cannot read your ChatGPT conversations. Tokens stay on the server.
            </p>
          </div>
        ) : (
          <div className="space-y-3 text-sm">
            <p className="text-mute">
              Not signed in. Agents fall back to a Claude credential on the operator&apos;s machine, if there is one.
            </p>
            <form action="/auth/start" method="post">
              <button className={button}>Sign in with ChatGPT</button>
            </form>
            <p className="text-xs text-mute">
              Open this dashboard as <span className="font-mono">http://127.0.0.1:3000</span> first: the sign-in can
              only return to a 127.0.0.1 address.
            </p>
          </div>
        )}
      </Panel>
    </div>
  );
}
