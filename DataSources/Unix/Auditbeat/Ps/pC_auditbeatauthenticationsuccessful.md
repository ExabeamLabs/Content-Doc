#### Parser Content
```Java
{
Name = auditbeat-authentication-successful
  Vendor = Unix
  Product = Auditbeat
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [""""auditbeat"""",""""action":"user_login"""",""""category":["authentication"""]
  Fields = [
    """timestamp":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)"""",
    """"hostname":"({host}[^"]{1,2000})"""",
    """"user":\{.+?name":"({user}[^"]{1,2000})"""",
    """"ip":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"action":"({event_name}[^"]{1,2000})"""",
    """"outcome":"({outcome}[^"]{1,2000})"""",
    """"message":"({additional_info}[^"]{1,2000})"""",
    """"domain":"({domain}[^"]{1,2000})"""",
  ]
  DupFields = ["host->dest_host"]
}
```