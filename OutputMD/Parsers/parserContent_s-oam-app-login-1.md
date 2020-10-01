#### Parser Content
```Java
{
Name = s-oam-app-login-1
  Vendor = Oracle
  Product = Oracle Access Manager
  Lms = Splunk
  DataType = "app-login"
  IsHVF = true
  TimeFormat = "MM\\/dd\\/yyyy HH:mm:ss \\Z"
  Conditions = [ """- AUTH""", """_SUCCESS -""", """- 2uid=""" ]
  Fields = [
    """({time}\d\d\\\/\d\d\\\/\d\d\d\d \d\d:\d\d:\d\d \\(-|\+)\d\d\d\d)\s+-\s*({subtype}.*?)\s+-\s*({method}.*?)\s+-\s*({host}.*?)\s+-\s*({dest_ip}.*?)\s+-\s*({app}.*?)\s+-\s*({ldap}.*?)\s+-\s*({clock}.*?)\s+-\s*({protocol}.*?)\s+-\s*({dest_host}.*?)\s+-"""   
    """- 2uid=({user}[^\s]+)""" 
  ]
}
```