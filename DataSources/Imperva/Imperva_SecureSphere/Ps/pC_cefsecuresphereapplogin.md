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
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """\srt=({time}\w+ \d{1,100} \d{4} \d\d:\d\d:\d\d)""",
    """0\|([^\|]{0,2000}\|){4}.+?logged in from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """0\|([^\|]{0,2000}\|){4}User ({user}[^\s]{1,2000}) logged in from""",
    """\ssuser=({user}.+?)\s{0,100}(\w+=|$)"""
  ]
}
```