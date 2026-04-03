import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  experimental: {
    serverActions: {
      // Allow Server Actions originating from the Go proxy (HTTPS termination point).
      // The proxy forwards X-Forwarded-Host so Next.js can verify the CSRF check.
      allowedOrigins: [
        'localhost:8443',
        process.env.ALLOWED_ORIGIN ?? '',
      ].filter(Boolean),
    },
  },
}

export default nextConfig
