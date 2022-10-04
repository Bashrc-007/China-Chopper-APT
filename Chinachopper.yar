rule Searching_ChinaChopper {
meta:
description = "China Chopper Webshells - PHP and ASPX"
strings:
$aspx = /%@\sPage\sLanguage=.Jscript.%><%eval\(Request\.Item\[.{,100}unsafe/
$php = /<?php.\@eval\(\$_POST./
condition:
1 of them
}
