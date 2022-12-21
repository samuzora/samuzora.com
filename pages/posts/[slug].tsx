import Markdown from "markdown-to-jsx"
import { GetStaticProps } from "next"
import { ParsedUrlQuery } from "querystring"
import Container from "../../components/Container"
import { getPost, getSlugs, Post } from "../../server/posts"

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
      <Markdown>{props.post.content}</Markdown>
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
  return { paths: [], fallback: true }
}
