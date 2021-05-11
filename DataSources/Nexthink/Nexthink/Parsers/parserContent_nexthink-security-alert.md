#### Parser Content
```Java
{
Name = nexthink-security-alert
  Vendor = Nexthink
  Product = Nexthink
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ source [""", """ computer_type="""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)\s{1,100}({host}[\w.\-]+)\s{1,100}(\S+\s{1,100}){2}source \[.*?\] \[({alert_type}[^\[\]]+?)\] ({alert_name}.+?)\s{1,100}\[""",
    """name="({src_host}[^"]+)""",
    """os_name="({os}[^"]+)""",
    """last_login_user="({user}[^@"]+)@({domain}[^@"]+)""",
  ]
}
```