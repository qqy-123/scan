import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true, // every route becomes a dir → works with FastAPI StaticFiles(html=True)
  images: { unoptimized: true },
};

export default nextConfig;
