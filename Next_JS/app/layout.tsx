import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Bot Detection Engine',
  description: 'TLS + JS behavioral fingerprint analysis',
  icons: {
    icon: "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🤖</text></svg>",
  },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-surface antialiased">
        {children}
      </body>
    </html>
  )
}
