import 'rsuite/dist/rsuite.min.css'
import '../styles/globals.css'
import type { AppProps } from 'next/app'
import { IBM_Plex_Sans } from '@next/font/google'
import Navbar from '../components/Navbar'
import { useRouter } from 'next/router'
import Loading from '../components/Loading'

const font = IBM_Plex_Sans({
  weight: '300',
  subsets: ['latin'],
})

export default function App({ Component, pageProps }: AppProps) {
  const router = useRouter()

  if (router.isFallback) {
    return (
      <Loading />
    )
  } else {
    return (
      <main className={font.className}>
        <div className="background" />
        <Navbar />
        <Component {...pageProps} />
      </main>
    )
  }
}
