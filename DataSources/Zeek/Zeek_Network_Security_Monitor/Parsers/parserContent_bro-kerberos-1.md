#### Parser Content
```Java
{
Name = bro-kerberos-1
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "remote-access"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"id.orig_h":""", """"id.resp_h":""", """"kerberos",""" ]
  Fields = [
    """exabeam_host=([^@=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"ts":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid":"({conn_id}[^"]{1,2000})""",
    """"id\.orig_h":"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.orig_p":({src_port}\d{1,100})""",
    """"id\.resp_h":"({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.resp_p":({dest_port}\d{1,100})""",
    """"client":"({user}[^"\\\/]{1,2000})[\\\/]{1,2000}({domain}[^"\\\/]{1,2000})""",
    """"service":"({service_name}[^"]{1,2000})""",
    """"success":({outcome}[^,]{1,2000})""",
    """"error_msg":"({result_code}[^"]{1,2000})""",
    """"cipher":"({ticket_encryption_type}[^"]{1,2000})""",
  ]
}
```