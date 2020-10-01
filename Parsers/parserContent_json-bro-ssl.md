#### Parser Content
```Java
{
Name = json-bro-ssl
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "authentication-successful"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """/ssl.log""", """"id.orig_h\":""", """"id.resp_h\":""", """"id.orig_p\":""", """"id.resp_p\":""" ]
  Fields = [
    """"HOST"+:\s*"+({host}[^"]+)"""",
    """"TAGS"+:\s*"+({event_code}[^"]+)"""",
    """"ts\\?"+:\\?"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"id\.orig_h\\?"+:\\?"+({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"+:({src_port}\d+)""",
    """"id\.resp_h\\?"+:\\?"+({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"+:({dest_port}[a-fA-F\d.:]+)""",
    """"version\\?"+:\\?"+({service}[^"\\]+)""",
    """"cipher\\?"+:\\?"+({auth_method}[^"\\]+)"""
    """"established\\?"+:({outcome}\w+)""" 
  ]
}
```