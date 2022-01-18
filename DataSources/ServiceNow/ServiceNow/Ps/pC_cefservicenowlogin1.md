#### Parser Content
```Java
{
Name = cef-servicenow-login-1
  Conditions = [ """CEF:""", """|Skyformation|""", """destinationServiceName =ServiceNow""", """"name":"login"""" ]

servicenow-login-template = {
    Vendor = ServiceNow
    Product = ServiceNow
    Lms = ArcSight
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_host=([^=]{0,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
      """"sys_created_on":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """destinationServiceName =({app}ServiceNow)""",
      """\Wsuser=((?i)(anonymous)|({user}[^\s@]{1,2000}?)@({domain}[^\s@]{1,2000})|({=user}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
      """"user(_name)?":"((?i)(anonymous)|({user}[^"\s@]{1,2000})@({domain}[^"\s@]{1,2000})|({=user}[^"\s@]{1,2000}))"""",
      """"name":"({object}[^"]{1,2000})""",
      """CEF:([^\|]{0,2000}\|){5}({event_name}[^\|]{1,2000})""",
      """"queue":"({event_name}[^"]{1,2000})""",
      """"parm1":"\s{0,100}(|-|({resource}[^",]{1,2000}?[^\\\s])\s{0,100})",""",
      """"parm2":"({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    
}
```