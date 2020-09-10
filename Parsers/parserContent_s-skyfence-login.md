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
    """\sdvc="+({host}[^"]+)""",
    """\sdvchost="+({host}[^"]+)""",
    """\srt="+({time}\d+)""",
    """\sduser="+({user}[^"]+)""",
    """\sduser="+[^@"]+@({domain}[^".]+)""",
    """\sdestinationServiceName="({app}[^"]+)"""",
    """\sapp="({app}[^"]+)"""",
    """\srequestClientApplication=({user_agent}.+?)\s+rt=""",
    """\sdst="+({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssrc="+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\soutcome="+({outcome}[^"]+)""",
    """\sdpriv="+({privileges}[^"]+)""",
    """\srequestClientApplication="+[^"]+"+.*?({browser}trident/7.0)""",
    """\srequestClientApplication="+[^"]+"+.*?({os}windows[^;)]*)""",
    """\srequestClientApplication="+[^"]+"+.*?mozilla[^\s]+\s*\(({os}[^\)]+).*({browser}[\d.]+\s+(mobile )?safari)""",
    """\srequestClientApplication="+[^"]+"+[^\s]+\s+\(((windows|x11|macintosh|u|compatible);( (u|i);)?\s+)?({os}[^;\)]+).*\s({browser}(chrome|firefox|version)\/\d+)""",
    """\srequestClientApplication="+[^"]+"+.*({browser}msie\s+\d[^\s,;\)]+)""",
    """\srequestClientApplication=".*?(({os}iOS|Android|BlackBerry|(W|w)indows Phone|BeOS|(X|x)11|(W|w)indows|(L|l)inux|(M|m)acintosh|(D|d)arwin).+?({browser}(C|c)hrome|(S|s)afari|(O|o)pera|(F|f)irefox|MSIE|(T|t)rident|(A|a)pple(W|w)ebkit))"""
  ]
}
```