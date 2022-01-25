#### Parser Content
```Java
{
Name = cef-servicenow-login-1
  Conditions = [ """destinationServiceName =ServiceNow""", """"name":"login"""" ]

servicenow-login-template = {
    Vendor = ServiceNow
    Product = ServiceNow
    Lms = ArcSight
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_host=([^=]{0,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
      """"sys_created_on":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({app}ServiceNow)""",
      """"user(_name)?":"((?i)(anonymous)|({user}[^"\s@]{1,2000})@({domain}[^"\s@]{1,2000})|({=user}[^"\s@]{1,2000}))"""",
      """"name":"({object}[^"]{1,2000})""",
      """"name":"({event_name}[^"]{1,2000})"""",
      """"queue":"({event_name}[^"]{1,2000})""",
      """"parm1":"\s{0,100}(|-|({resource}[^",]{1,2000}?[^\\\s])\s{0,100})",""",
      """"parm2":"({src_ip}[A-Fa-f\d:.]{1,2000})"""",
    
}
```