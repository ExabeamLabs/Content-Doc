#### Parser Content
```Java
{
Name = json-bro-weird
  Vendor = Bro
  Lms = Direct
  DataType = "network-alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """/weird.log""", """"id.orig_h\":""", """"id.resp_h\":""", """"name\":""", """"peer\":""" ]
  Fields = [
    """"HOST"+:\s*"+({host}[^"]+)"""",
    """"TAGS"+:\s*"+({alert_type}[^"]+)"""",
    """"ts\\?"+:\\?"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"id\.orig_h\\?"+:\\?"+({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"+:({src_port}\d+)""",
    """"id\.resp_h\\?"+:\\?"+({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"+:({dest_port}[a-fA-F\d.:]+)""",
    """"name\\?"+:\\?"+({alert_name}[^"\\]+)""",
    """"peer\\?"+:\\?"+({src_host}[^"\\]+)"""
  ]
}
```