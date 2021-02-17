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
    """timestamp":"({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)"""",
    """"hostname":"({host}[^"]+)"""",
    """"user":\{.+?name":"({user}[^"]+)"""",
    """"ip":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"action":"({event_name}[^"]+)"""",
    """"outcome":"({outcome}[^"]+)"""",
    """"message":"({additional_info}[^"]+)"""",
    """"domain":"({domain}[^"]+)"""",
  ]
  DupFields = ["host->dest_host"]
}
```