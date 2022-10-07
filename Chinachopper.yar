rule Searching_ChinaChopper {
meta:
description = "China Chopper Webshells - PHP and ASPX"
strings:
$s0 = /%@\sPage\sLanguage=.Jscript.%><%eval\(Request\.Item\[.{,100}unsafe/
$s1 = /<?php.\@eval\(\$_POST./
$s2 = { 65 76 61 6C 28 } 
$s3 = { 28 52 65 71 75 65 73 74 2E 49 74 65 6D 5B [1-36] 5D 29 29 2C 22 75 6E 73 61 66 65 22 29 }
$s4 = { 49 4F 2E 53 74 72 65 61 6D 57 72 69 74 65 72 28 52 65 71 75 65 73 74 2E 46 6F 72 6D 5B [1-24] 5D }
$s5 = { 57 72 69 74 65 28 52 65 71 75 65 73 74 2E 46 6F 72 6D 5B [1-24] 5D }
condition:
 2 of ($s*)
}
