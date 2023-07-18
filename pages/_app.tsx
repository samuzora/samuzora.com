import 'rsuite/dist/rsuite.min.css'
import '../styles/globals.css'
import type { AppProps } from 'next/app'
import { IBM_Plex_Sans } from '@next/font/google'
import Navbar from '../components/Navbar'
import { useRouter } from 'next/router'
import Loading from '../components/Loading'
import Container from '../components/Container'
import Link from 'next/link'

import TwitterIcon from '@mui/icons-material/Twitter';
import InstagramIcon from '@mui/icons-material/Instagram';
import GitHubIcon from '@mui/icons-material/GitHub';

import styles from "../styles/app.module.scss"

const font = IBM_Plex_Sans({
  weight: '300',
  subsets: ['latin'],
})

export default function App({ Component, pageProps }: AppProps) {
  const router = useRouter()

  if (router.isFallback) {
    return (
      <main className={font.className}>
        <div className="background" />
        <Navbar />
        <Container>
          <Loading />
        </Container>
      </main>
    )
  } else {
    return (
      <main className={font.className}>
        <div className="background" />
        <Navbar />
        <Component {...pageProps} />
        <div className={styles.footer}>
          <Link href="https://twitter.com/_samuzora">
            <TwitterIcon />
          </Link>
          <Link href="https://www.instagram.com/samu_zora/">
            <InstagramIcon />
          </Link>
          <Link href="https://github.com/samuzora">
            <GitHubIcon />
          </Link>
        </div>
      </main>
    )
  }
}
