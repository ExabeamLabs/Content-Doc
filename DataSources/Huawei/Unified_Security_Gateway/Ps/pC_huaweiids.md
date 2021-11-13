#### Parser Content
```Java
{
Name = huawei-ids
  Conditions = ["""SignName =""" , """SignId=""" , """Os=""" ,  """IPS/"""]

huawei-ids = {
  Vendor = Huawei
  Product = Unified Security Gateway
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Fields = [
     """({time}\d\d\d\d-\d\d-\d\d\s{0,100}\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)\s({host}[^\s]{1,2000})\s{0,100}%""",
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d),\S+\s{1,100}({host}[\w\.\-]{1,2000})""",
     """SrcPort=({src_port}[^,]{1,2000})""",
     """SrcIp=({src_ip}[^,]{1,2000})""",
     """DstPort=({dest_port}[^,]{1,2000})""",
     """DstIp=({dest_ip}[^,]{1,2000})""",
     """Protocol=({protocol}[^,]{1,2000})""",
     """Application="({app}[^"]{1,2000})""",
     """SignName ="({alert_name}[^"]{1,2000})""",
     """Severity=({alert_severity}[^,]{1,2000})""",
     """Category=({alert_type}[^,]{1,2000})""",
     """Policy="({policy}[^"]{1,2000})""",
     """User="(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:unknown|({user_email}[^@"]{1,2000}@[^@"]{1,2000})|({user}[^"]{1,2000}))""""
  
}
```