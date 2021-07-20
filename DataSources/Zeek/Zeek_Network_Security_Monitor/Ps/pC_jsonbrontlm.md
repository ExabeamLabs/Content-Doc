#### Parser Content
```Java
{
Name = json-bro-ntlm
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "ntlm-logon"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """/ntlm.log""", """"hostname\":""", """"uid\":""", """"id.orig_h\":""", """"id.resp_h\":""" ]
  Fields = [
    """"HOST"{1,20}:\s{0,100}"{1,20}({host}[^"]{1,2000})"""",
    """"TAGS"{1,20}:\s{0,100}"{1,20}({event_code}[^"]{1,2000})"""",
    """"ts\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"username\\?"{1,20}:\\?"{1,20}({user}[^"\\]{1,2000})""",
    """"id\.orig_h\\?"{1,20}:\\?"{1,20}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.resp_p\\?"{1,20}:({dest_port}[a-fA-F\d.:]{1,2000})""",
    """"hostname\\?"{1,20}:\\?"{1,20}({src_host}[^"\\]{1,2000})""",
    """"success\\?"{1,20}:({outcome}\w+)"""
  ]
}
```