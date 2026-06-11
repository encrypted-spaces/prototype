import type { Metadata } from "next";
import "./globals.css";
import { SpaceProvider } from "@/lib/store";

export const metadata: Metadata = {
  title: "SPACES",
  description: "Verifiable encrypted chat",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <SpaceProvider>{children}</SpaceProvider>
      </body>
    </html>
  );
}
