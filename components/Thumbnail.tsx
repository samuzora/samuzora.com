import Link from "next/link"
import { useRouter } from "next/router"
import { Post } from "../server/posts"
import styles from "../styles/Thumbnail.module.scss"

interface Props {
  post: Post
}

export default function Thumbnail(props: Props) {
  const router = useRouter()
  return (
    <>
      <Link href={`posts/${props.post.slug}`}>
        <div className={styles.card}>
          <div className={styles.title}>{props.post.title}</div>
          <b>{props.post.date}</b>
        </div>
      </Link>
    </>
  )
}
