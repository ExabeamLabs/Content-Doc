#### Parser Content
```Java
{
Name = json-bro-weird
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "network-alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """/weird.log""", """"id.orig_h\":""", """"id.resp_h\":""", """"name\":""", """"peer\":""" ]
  Fields = [
    """"HOST"{1,20}:\s{0,100}"{1,20}({host}[^"]+)"""",
    """"TAGS"{1,20}:\s{0,100}"{1,20}({alert_type}[^"]+)"""",
    """"ts\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"id\.orig_h\\?"{1,20}:\\?"{1,20}({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"{1,20}:({dest_port}[a-fA-F\d.:]+)""",
    """"name\\?"{1,20}:\\?"{1,20}({alert_name}[^"\\]+)""",
    """"peer\\?"{1,20}:\\?"{1,20}({src_host}[^"\\]+)"""
  ]
}
```