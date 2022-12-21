import fs from 'fs'
import Markdown from 'markdown-to-jsx'
import { GetStaticProps } from 'next'
import Head from 'next/head'
import { resolve } from 'path'
import Container from '../components/Container'
import styles from '../styles/Home.module.scss'

interface Props {
  content: string
}

export default (props: Props) => {
  return (
    <div>
      <Head>
        <title>samuzora</title>
      </Head>
      <Container>
        <div className={styles.greeter}>
          samuzora
        </div>
        <Markdown className={styles.content}>{props.content}</Markdown>
      </Container>
    </div>
  )
}

export const getStaticProps: GetStaticProps<Props> = async () => {
  const filename = resolve('_about.md')
  const content = fs.readFileSync(filename, { encoding: "utf8" })
  return {
    props: { content }
  }
}
