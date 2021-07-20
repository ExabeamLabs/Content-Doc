#### Parser Content
```Java
{
Name = cef-infowatch-app-login
  Vendor = InfoWatch
  Product = InfoWatch
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|DLP TM6 Audit|""", """cat=User""", """act=login""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wsuser=({user}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wsuid=({user_fullname}.+?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wad\.user__email=({user_email}[^@]{1,2000}@({email_domain}.+?))(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """"hostname":"({host}[^"]{1,2000})"""",
    """"ip":"({dest_ip}[^"]{1,2000})"""",
    """"login":"({user}[^"]{1,2000})"""",
  ]
  DupFields = [ "host->app" ]
}
```