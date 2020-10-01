#### Parser Content
```Java
{
Name = cef-duo-app-login
  Vendor = Cisco
  Product = Duo Access Security
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """|Duo Security|Two-factor|""" , """outcome=SUCCESS"""]
  Fields = [
    """\s\d\d:\d\d:\d\d ({host}[^\s=]+)""",
    """\sduser=({user}.+?)\s+\w+=""",
    """\sintegration=({app}.+?)\s+\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```