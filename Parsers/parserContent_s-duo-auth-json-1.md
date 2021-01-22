#### Parser Content
```Java
{
Name = s-duo-auth-json-1
  Vendor = Duo Security
  Product = Duo Security
  Lms = Splunk
  DataType = "authentication-attempt"
  TimeFormat = "epoch_sec"
  Conditions = [ """"eventtype": "authentication"""",""""result""""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """"+timestamp"+:\s({time}\d+)""",
    """"+host"+:\s"+({host}[\w\-\.]+)"""",
    """"+ip"+:\s"+(0.0.0.0|({src_ip}[a-fA-F:\.\d]+))"""",
    """"+username"+:\s"+(({domain}[^\\]+)\\+)?({user}[^"]+)"""",
    """"+integration"+:\s"+({auth_method}[^"]+)"""",
    """"+device"+:\s(null|"+({device}[^"]+))""",
    """"+result"+:\s"+({outcome}[^"]+)"""",
    """"+reason"+:\s"+({failure_reason}[^"]+)""""
  ]
}
```