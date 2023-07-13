import { getSlugs } from "../server/posts"

//pages/sitemap.xml.js
const EXTERNAL_DATA_URL = 'https://samuzora.com/posts'

export default function SiteMap() {
  // empty cos we just want getServerSideProps
}


function generateSiteMap(posts: string[]) {
  return `<?xml version="1.0" encoding="UTF-8"?>
   <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
     <url>
       <loc>https://samuzora.com</loc>
     </url>
     <url>
       <loc>https://samuzora.com/posts</loc>
     </url>
     ${posts
       .map(post => {
         return `
       <url>
           <loc>${`${EXTERNAL_DATA_URL}/${post}`}</loc>
       </url>
     `
       })
       .join('')}
   </urlset>
 `
}

export async function getServerSideProps({ res }) {
  const posts = await getSlugs()

  // We generate the XML sitemap with the posts data
  const sitemap = generateSiteMap(posts)

  res.setHeader('Content-Type', 'text/xml')
  // we send the XML to the browser
  res.write(sitemap)
  res.end()

  return {
    props: {},
  }
}
