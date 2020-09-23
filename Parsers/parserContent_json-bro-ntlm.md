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
    """"HOST"+:\s*"+({host}[^"]+)"""",
    """"TAGS"+:\s*"+({event_code}[^"]+)"""",
    """"ts\\?"+:\\?"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"username\\?"+:\\?"+({user}[^"\\]+)""",
    """"id\.orig_h\\?"+:\\?"+({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"+:({src_port}\d+)""",
    """"id\.resp_h\\?"+:\\?"+({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"+:({dest_port}[a-fA-F\d.:]+)""",
    """"hostname\\?"+:\\?"+({src_host}[^"\\]+)""",
    """"success\\?"+:({outcome}\w+)"""
  ]
}
```