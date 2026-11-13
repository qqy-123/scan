"use client";
import { useEffect } from "react";

export default function Home() {
  useEffect(() => {
    location.replace("/dashboard/");
  }, []);
  return null;
}
