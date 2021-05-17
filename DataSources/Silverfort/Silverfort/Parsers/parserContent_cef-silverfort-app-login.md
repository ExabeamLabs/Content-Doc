#### Parser Content
```Java
{
Name = cef-silverfort-app-login
  Vendor = Silverfort
  Product = Silverfort
  Lms = Direct
  DataType = "app-login"
  TimeFormat ="dd/MM/yyyy HH:mm:ss.SSS"
  Conditions = [ """ CEF:""", """|Silverfort|Admin Console|""", """|Authentication|Authentication request|""" ]
  Fields = [
    """\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}CEF:""",
    """rt=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d.\d\d\d)""",
    """suser=(({user_email}[^@]{1,2000}@({email_domain}[^\s]{1,2000}))|({user}.+?))\ssntdom=""",
    """sntdom=({domain}[^\s]{1,2000})""",
    """shost=(n\/a|({src_host}[^\s]{1,2000}))""",
    """src=(n\/a|({src_ip}[a-fA-F\d\.:]{1,2000}))""",
    """dhost=(n\/a|({dest_host}[^\s]{1,2000}))""",
    """app=(n\/a|({app}[^\s]{1,2000}))""",
    """cs2=({outcome}[^\s]{1,2000})""",
  ]
}
```