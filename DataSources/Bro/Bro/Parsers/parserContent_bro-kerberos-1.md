#### Parser Content
```Java
{
Name = bro-kerberos-1
  Vendor = Bro
  Product = Bro
  Lms = Direct
  DataType = "remote-access"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"id.orig_h":""", """"id.resp_h":""", """"kerberos",""" ]
  Fields = [
    """exabeam_host=([^@=]+@\s*)?({host}\S+)""",
    """"ts":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid":"({conn_id}[^"]+)""",
    """"id\.orig_h":"({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p":({src_port}\d+)""",
    """"id\.resp_h":"({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p":({dest_port}\d+)""",
    """"client":"({user}[^"\\\/]+)[\\\/]+({domain}[^"\\\/]+)""",
    """"service":"({service_name}[^"]+)""",
    """"success":({outcome}[^,]+)""",
    """"error_msg":"({result_code}[^"]+)""",
    """"cipher":"({ticket_encryption_type}[^"]+)""",
  ]
}
```