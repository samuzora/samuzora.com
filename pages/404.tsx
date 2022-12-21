import styles from '../styles/404.module.scss'
import { IBM_Plex_Sans } from '@next/font/google'
import Navbar from '../components/Navbar'
import { useRouter } from 'next/router'
import Loading from '../components/Loading'
import Container from '../components/Container'

const font = IBM_Plex_Sans({
  weight: '300',
  subsets: ['latin'],
})


export default () => {
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
        <Container className={styles.text}>
          <div className={styles.text}>
            <h1>404!?</h1>
            page not found
          </div>
        </Container>
      </main>
    )
  }
}
