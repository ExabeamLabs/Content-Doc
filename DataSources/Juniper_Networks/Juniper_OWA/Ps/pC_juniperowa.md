#### Parser Content
```Java
{
Name = juniper-owa
  Vendor = Juniper Networks
  Product = Juniper OWA
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "AUT22670", "Login succeeded for" ]
  Fields = [
    """\sfw=({host}[\w\-\.]{1,2000})""",
    """\w+\s{0,100}\d{1,100}\s{0,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w.\-]{1,2000})\s{0,100}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d""",
    """\stime="{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100}).+?user""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s""",
    """user=({user}.+?)\s{1,100}realm=""",
    """realm="{1,20}({app}[^"]{1,2000})""",
    """agent="{1,20}({user_agent}[^"]{1,2000})"""",
  ]
}
}
```