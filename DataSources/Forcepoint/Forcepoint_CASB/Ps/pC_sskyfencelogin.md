#### Parser Content
```Java
{
Name = s-skyfence-login
  Vendor = Forcepoint
  Product = Forcepoint CASB
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ "CEF", "Skyfence", """|Activity|""", """reason="login"""" ]
  Fields = [
    """\sdvc="{1,20}({host}[^"]{1,2000})""",
    """\sdvchost="{1,20}({host}[^"]{1,2000})""",
    """\srt="{1,20}({time}\d{1,100})""",
    """\sduser="{1,20}({user}[^"]{1,2000})""",
    """\sduser="{1,20}[^@"]{1,2000}@({domain}[^".]{1,2000})""",
    """\sdestinationServiceName ="({app}[^"]{1,2000})"""",
    """\sapp="({app}[^"]{1,2000})"""",
    """\srequestClientApplication=({user_agent}.+?)\s{1,100}rt=""",
    """\sdst="{1,20}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssrc="{1,20}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\soutcome="{1,20}({outcome}[^"]{1,2000})""",
    """\sdpriv="{1,20}({privileges}[^"]{1,2000})""",
    """\srequestClientApplication="{1,20}[^"]{1,2000}"{1,20}.*?({browser}trident/7.0)""",
    """\srequestClientApplication="{1,20}[^"]{1,2000}"{1,20}.*?({os}windows[^;)]{0,2000})""",
    """\srequestClientApplication="{1,20}[^"]{1,2000}"{1,20}.*?mozilla[^\s]{1,2000}\s{0,100}\(({os}[^\)]{1,2000}).*({browser}[\d.]{1,2000}\s{1,100}(mobile )?safari)""",
    """\srequestClientApplication="{1,20}[^"]{1,2000}"{1,20}[^\s]{1,2000}\s{1,100}\(((windows|x11|macintosh|u|compatible);( (u|i);)?\s{1,100})?({os}[^;\)]{1,2000}).*\s({browser}(chrome|firefox|version)\/\d{1,100})""",
    """\srequestClientApplication="{1,20}[^"]{1,2000}"{1,20}.*({browser}msie\s{1,100}\d[^\s,;\)]{1,2000})""",
    """\srequestClientApplication=".*?(({os}iOS|Android|BlackBerry|(W|w)indows Phone|BeOS|(X|x)11|(W|w)indows|(L|l)inux|(M|m)acintosh|(D|d)arwin).+?({browser}(C|c)hrome|(S|s)afari|(O|o)pera|(F|f)irefox|MSIE|(T|t)rident|(A|a)pple(W|w)ebkit))"""
  ]


}
```