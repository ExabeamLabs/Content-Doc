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
    """\s{1,100}({host}[\w\-.]+)\s{1,100}CEF:""",
    """rt=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d.\d\d\d)""",
    """suser=(({user_email}[^@]+@({email_domain}[^\s]+))|({user}.+?))\ssntdom=""",
    """sntdom=({domain}[^\s]+)""",
    """shost=(n\/a|({src_host}[^\s]+))""",
    """src=(n\/a|({src_ip}[a-fA-F\d\.:]+))""",
    """dhost=(n\/a|({dest_host}[^\s]+))""",
    """app=(n\/a|({app}[^\s]+))""",
    """cs2=({outcome}[^\s]+)""",
  ]
}
```