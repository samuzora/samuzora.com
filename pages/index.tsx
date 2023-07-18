import fs from 'fs'
import Markdown from 'markdown-to-jsx'
import { GetStaticProps } from 'next'
import Head from 'next/head'
import { join } from 'path'
import Container from '../components/Container'
import styles from '../styles/Home.module.scss'
import Link from 'next/link'

import TwitterIcon from '@mui/icons-material/Twitter';
import InstagramIcon from '@mui/icons-material/Instagram';
import GitHubIcon from '@mui/icons-material/GitHub';
import AccessibleIcon from '@mui/icons-material/Accessible';

interface Props {
  content: string
}

export default (props: Props) => {
  return (
    <div>
      <Head>
        <title>samuzora</title>
        <meta
          name="description"
          content="samuzora's blog - ctfs and more stuff"
          key="desc"
        />
      </Head>
      <Container>
        <div className={styles.greeter}>
          samuzora
        </div>
        <Markdown className={styles.content}>{props.content}</Markdown>
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
      </Container>
    </div>
  )
}

export const getStaticProps: GetStaticProps<Props> = async () => {
  const filename = join(process.cwd(), "_about.md")
  const content = fs.readFileSync(filename, { encoding: "utf8" })
  return {
    props: { content },
  }
}
