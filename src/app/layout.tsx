import type { Metadata } from "next";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

export const metadata: Metadata = {
  title: "OmniAgent Studio — Visual Agent Runtime",
  description:
    "Cyberpunk visual IDE for autonomous agents: React Flow canvas with live browser takeover, LLM thought streams and real-time metric dashboards.",
  keywords: ["OmniAgent", "React Flow", "AI agents", "browser automation", "ECharts", "cyberpunk", "dev tools"],
  authors: [{ name: "OmniAgent Studio" }],
  openGraph: {
    title: "OmniAgent Studio",
    description: "Visual agent runtime — browser takeover, LLM streams, live dashboards",
    url: "https://chat.z.ai",
    siteName: "OmniAgent Studio",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "OmniAgent Studio",
    description: "Visual agent runtime — browser takeover, LLM streams, live dashboards",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className="antialiased bg-background text-foreground">
        {children}
        <Toaster />
      </body>
    </html>
  );
}
