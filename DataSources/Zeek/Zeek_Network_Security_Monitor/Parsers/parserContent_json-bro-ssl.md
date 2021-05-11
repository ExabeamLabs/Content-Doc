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
    """"HOST"{1,20}:\s{0,100}"{1,20}({host}[^"]+)"""",
    """"TAGS"{1,20}:\s{0,100}"{1,20}({event_code}[^"]+)"""",
    """"ts\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"id\.orig_h\\?"{1,20}:\\?"{1,20}({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"{1,20}:({dest_port}[a-fA-F\d.:]+)""",
    """"version\\?"{1,20}:\\?"{1,20}({service}[^"\\]+)""",
    """"cipher\\?"{1,20}:\\?"{1,20}({auth_method}[^"\\]+)"""
    """"established\\?"{1,20}:({outcome}\w+)""" 
  ]
}
```