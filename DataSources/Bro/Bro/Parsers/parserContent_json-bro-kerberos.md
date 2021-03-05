#### Parser Content
```Java
{
Name = json-bro-kerberos
  Vendor = Bro
  Product = Bro
  Lms = Direct
  DataType = "remote-access"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """/kerberos.log""", """"id.orig_h\":""", """"id.resp_h\":""" ]
  Fields = [
    """"HOST"+:\s*"+({host}[^"]+)"""",
    """"TAGS"+:\s*"+({event_code}[^"]+)"""",
    """"ts\\?"+:\\?"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"client\\?"+:\\?"+({user}[^"\\]+)""",
    """"id\.orig_h\\?"+:\\?"+({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"+:({src_port}\d+)""",
    """"id\.resp_h\\?"+:\\?"+({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"+:({dest_port}[a-fA-F\d.:]+)""",
    """"request_type\\?"+:\\?"+({request_type}[^"\\]+)""",
    """"client\\?"+:\\?"+({user}[^"\/\\]+)(\/({domain}[^"\\]+))?""",
    """"service\\?"+:\\?"+({service_name}[^"\/\\@]+)""",
    """"success\\?"+:({outcome}\w+)""",
    """"error_msg\\?"+:\\?"+({result_code}[^"\\]+)""",
    """"cipher\\?"+:\\?"+({ticket_encryption_type}[^"\\]+)"""
  ]
}
```