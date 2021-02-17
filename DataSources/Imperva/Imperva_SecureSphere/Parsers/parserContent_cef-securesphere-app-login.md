#### Parser Content
```Java
{
Name = cef-securesphere-app-login
  Vendor = Imperva 
  Product = Imperva SecureSphere
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|Imperva Inc.|SecureSphere""", """cat=SystemEvent""", """|User logged in|""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """\srt=({time}\w+ \d+ \d{4} \d\d:\d\d:\d\d)""",
    """0\|([^\|]*\|){4}.+?logged in from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """0\|([^\|]*\|){4}User ({user}[^\s]+) logged in from""",
    """\ssuser=({user}.+?)\s*(\w+=|$)"""
  ]
}
```