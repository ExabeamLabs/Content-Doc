#### Parser Content
```Java
{
Name = s-duo-auth-json-1
  Vendor = Cisco
  Product = Duo Access Security
  Lms = Splunk
  DataType = "authentication-attempt"
  TimeFormat = "epoch_sec"
  Conditions = [ """"eventtype": "authentication"""",""""result""""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """"{1,20}timestamp"{1,20}:\s({time}\d{1,100})""",
    """"{1,20}host"{1,20}:\s"{1,20}({host}[\w\-\.]{1,2000})"""",
    """"{1,20}ip"{1,20}:\s"{1,20}(0.0.0.0|({src_ip}[a-fA-F:\.\d]{1,2000}))"""",
    """"{1,20}username"{1,20}:\s"{1,20}(({domain}[^\\]{1,2000})\\+)?({user}[^"]{1,2000})"""",
    """"{1,20}integration"{1,20}:\s"{1,20}({auth_method}[^"]{1,2000})"""",
    """"{1,20}device"{1,20}:\s(null|"{1,20}({device}[^"]{1,2000}))""",
    """"{1,20}result"{1,20}:\s"{1,20}({outcome}[^"]{1,2000})"""",
    """"{1,20}reason"{1,20}:\s"{1,20}({failure_reason}[^"]{1,2000})""""
  ]
}
```