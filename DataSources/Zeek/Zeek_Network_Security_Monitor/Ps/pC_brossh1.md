#### Parser Content
```Java
{
Name = bro-ssh-1
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"id.orig_h":""", """"id.resp_h":""", """"ssh",""" ]
  Fields = [
    """exabeam_host=([^@=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"ts":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid":"({conn_id}[^"]{1,2000})""",
    """"id\.orig_h":"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.orig_p":({src_port}\d{1,100})""",
    """"id\.resp_h":"({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.resp_p":({dest_port}\d{1,100})""",
    """"direction":"({direction}[^"]{1,2000})""",
    """"client":"({client}[^"]{1,2000})""",
    """"server":"({server}[^"]{1,2000})""",
    """"auth_success":({outcome}[^,]{1,2000})""",
  ]


}
```