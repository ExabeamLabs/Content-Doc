#### Parser Content
```Java
{
Name = json-bro-dce_rpc
  Vendor = Bro
  Lms = Direct
  DataType = "remote-access"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """/dce_rpc.log""", """"id.orig_h\":""", """"id.resp_h\":""", """"endpoint\":""", """"operation\":""" ]
  Fields = [
    """"HOST"+:\s*"+({host}[^"]+)"""",
    """"TAGS"+:\s*"+({event_code}[^"]+)"""",
    """"ts\\?"+:\\?"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"id\.orig_h\\?"+:\\?"+({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"+:({src_port}\d+)""",
    """"id\.resp_h\\?"+:\\?"+({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"+:({dest_port}[a-fA-F\d.:]+)""",
    """"endpoint\\?"+:\\?"+({dest_host}[^"\\]+)""",
    """"operation\\?"+:\\?"+({process_name}[^"\\]+)"""
  ]
}
```