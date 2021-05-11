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
    """\sdvc="{1,20}({host}[^"]+)""",
    """\sdvchost="{1,20}({host}[^"]+)""",
    """\srt="{1,20}({time}\d{1,100})""",
    """\sduser="{1,20}({user}[^"]+)""",
    """\sduser="{1,20}[^@"]+@({domain}[^".]+)""",
    """\sdestinationServiceName="({app}[^"]+)"""",
    """\sapp="({app}[^"]+)"""",
    """\srequestClientApplication=({user_agent}.+?)\s{1,100}rt=""",
    """\sdst="{1,20}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssrc="{1,20}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\soutcome="{1,20}({outcome}[^"]+)""",
    """\sdpriv="{1,20}({privileges}[^"]+)""",
    """\srequestClientApplication="{1,20}[^"]+"{1,20}.*?({browser}trident/7.0)""",
    """\srequestClientApplication="{1,20}[^"]+"{1,20}.*?({os}windows[^;)]*)""",
    """\srequestClientApplication="{1,20}[^"]+"{1,20}.*?mozilla[^\s]+\s{0,100}\(({os}[^\)]+).*({browser}[\d.]+\s{1,100}(mobile )?safari)""",
    """\srequestClientApplication="{1,20}[^"]+"{1,20}[^\s]+\s{1,100}\(((windows|x11|macintosh|u|compatible);( (u|i);)?\s{1,100})?({os}[^;\)]+).*\s({browser}(chrome|firefox|version)\/\d{1,100})""",
    """\srequestClientApplication="{1,20}[^"]+"{1,20}.*({browser}msie\s{1,100}\d[^\s,;\)]+)""",
    """\srequestClientApplication=".*?(({os}iOS|Android|BlackBerry|(W|w)indows Phone|BeOS|(X|x)11|(W|w)indows|(L|l)inux|(M|m)acintosh|(D|d)arwin).+?({browser}(C|c)hrome|(S|s)afari|(O|o)pera|(F|f)irefox|MSIE|(T|t)rident|(A|a)pple(W|w)ebkit))"""
  ]
}
```