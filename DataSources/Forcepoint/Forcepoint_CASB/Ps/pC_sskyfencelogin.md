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
  ]


}
```