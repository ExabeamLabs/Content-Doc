#### Parser Content
```Java
{
Name = imprivata-app-activity-1
  DataType = "app-activity"
  Conditions = [ """Event: Agent Shutdown""" ]

imprivata-app-activity = {
  Vendor = Imprivata
  Product = Imprivata
  Lms = Direct
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000}) ({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """ServerIP:\s{0,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """User:\s{0,100}({user}[^\s\#]{1,2000})""",
    """Event:\s{0,100}({activity}.+?)\s{1,100}ServerIP:""",
    """({app}Imprivata)""",
  
}
```