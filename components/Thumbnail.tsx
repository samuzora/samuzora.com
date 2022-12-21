import { useRouter } from "next/router"
import { Panel } from "rsuite"
import { Post } from "../server/posts"
import styles from "../styles/Thumbnail.module.scss"

interface Props {
  post: Post
}

export default function Thumbnail(props: Props) {
  const router = useRouter()
  return (
    <>
      <div className={styles.card} onClick={() => router.push(`posts/${props.post.slug}`)}>
        <h4>{props.post.title}</h4>
        <b>{props.post.date}</b>
      </div>
    </>
  )
}
