import type { Metadata } from "next";
import { EARLY_BROWSER_ERROR_GUARD } from "./browser-errors";
import "./globals.css";

export const metadata: Metadata = {
  title: "GPWN Signal Map",
  description:
    "Explore devices, connections, recovered files, and research findings from packet captures.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <script
          data-gpwn-error-guard="resize-observer"
          dangerouslySetInnerHTML={{ __html: EARLY_BROWSER_ERROR_GUARD }}
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
