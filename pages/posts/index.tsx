import { GetStaticProps } from "next"
import Container from "../../components/Container"
import Thumbnail from "../../components/Thumbnail"
import { getPosts, Post } from "../../server/posts"

interface Props {
  posts: Array<Post>
}

export default (props: Props) => {
  return (
    <Container>
      {
        props.posts.length
          ? props.posts.map(post => <Thumbnail key={post.slug} post={post} />)
          : "Sorry, no posts yet!"
      }
    </Container>
  )
}

export const getStaticProps: GetStaticProps<Props> = async () => {
  const posts = await getPosts()
  return {
    props: {
      posts,
    }
  }
}
