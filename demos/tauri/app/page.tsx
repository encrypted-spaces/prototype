"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { checkSnapshot } from "@/lib/api";

export default function Home() {
  const router = useRouter();
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    checkSnapshot()
      .then((exists) => {
        router.replace(exists ? "/setup?restore=1" : "/setup");
      })
      .catch(() => {
        router.replace("/setup");
      })
      .finally(() => setChecking(false));
  }, [router]);

  if (checking) {
    return <div className="loading-container">Loading...</div>;
  }

  return null;
}
