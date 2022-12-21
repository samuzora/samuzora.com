import Link from 'next/link'
import styles from '../styles/Navbar.module.scss'
import React from 'react'

export default function Navbar() {
  return (
    <div className={styles.navbar}>
      <Link className={styles.link} href='/'>
        about
      </Link>
      <Link className={styles.link} href='/posts'>
        posts
      </Link>
    </div>
  )
  // return (
  //   <Nav className={styles.navbar}>
  //     <Nav.Item as={Link} href='/'>
  //       about
  //     </Nav.Item>
  //     <Nav.Item as={Link} href='/posts'>
  //       posts
  //     </Nav.Item>
  //   </Nav>
  // )
}
