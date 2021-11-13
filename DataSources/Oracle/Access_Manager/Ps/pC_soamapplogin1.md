#### Parser Content
```Java
{
Name = s-oam-app-login-1
  Vendor = Oracle
  Product = Access Manager
  Lms = Splunk
  DataType = "app-login"
  IsHVF = true
  TimeFormat = "MM\\/dd\\/yyyy HH:mm:ss \\Z"
  Conditions = [ """- AUTH""", """_SUCCESS -""", """- 2uid=""" ]
  Fields = [
    """({time}\d\d\\\/\d\d\\\/\d\d\d\d \d\d:\d\d:\d\d \\(-|\+)\d\d\d\d)\s{1,100}-\s{0,100}({subtype}.*?)\s{1,100}-\s{0,100}({method}.*?)\s{1,100}-\s{0,100}({host}.*?)\s{1,100}-\s{0,100}({dest_ip}.*?)\s{1,100}-\s{0,100}({app}.*?)\s{1,100}-\s{0,100}({ldap}.*?)\s{1,100}-\s{0,100}({clock}.*?)\s{1,100}-\s{0,100}({protocol}.*?)\s{1,100}-\s{0,100}({dest_host}.*?)\s{1,100}-"""   
    """- 2uid=({user}[^\s]{1,2000})""" 
  ]


}
```