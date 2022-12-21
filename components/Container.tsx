import { ScriptProps } from 'next/script'
import styles from '../styles/Container.module.scss'

export default function Container(props: ScriptProps) {
  return (
    <div className={styles.container}>
      {props.children}
    </div>
  )
}
