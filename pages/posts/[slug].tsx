import { GetStaticProps } from "next"
import { ParsedUrlQuery } from "querystring"
import { ReactMarkdown } from "react-markdown/lib/react-markdown"
import Container from "../../components/Container"
import { getPost, getSlugs, Post } from "../../server/posts"
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { coldarkDark } from 'react-syntax-highlighter/dist/cjs/styles/prism'

interface Props {
  post: Post
}

interface Params extends ParsedUrlQuery {
  slug: string
}

export default (props: Props) => {
  return (
    <Container>
      <h1>{props.post.title}</h1>
      <h5>{props.post.date}</h5>
      <hr />
      <ReactMarkdown
        children={props.post.content}
        components={{
          code({ node, inline, className, children, ...props }) {
            const match = /language-(\w+)/.exec(className || '')
            return !inline && match ? (
              <SyntaxHighlighter
                children={String(children).replace(/\n$/, '')}
                style={coldarkDark}
                language={match[1]}
                PreTag="div"
              // {...props}
              />
            ) : (
              <code className={className} {...props}>
                {children}
              </code>
            )
          }
        }} />
    </Container>
  )
}

export const getStaticProps: GetStaticProps<Props, Params> = async (context) => {
  const params = context.params!
  const post = await getPost(params.slug)
  return {
    props: { post }
  }
}

export async function getStaticPaths() {
  const slugs = await getSlugs()
  return { paths: slugs.map(slug => `/posts/${slug}`), fallback: true }
}
