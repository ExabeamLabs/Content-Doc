#### Parser Content
```Java
{
Name = bro-smb_mapping-1
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "share-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"smb_mapping",""", """"id.orig_h":""", """"id.resp_h":""" ]
  Fields = [
    """exabeam_host=([^@=]+@\s{0,100})?({host}\S+)""",
    """"ts":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid":"({conn_id}[^"]+)""",
    """"id\.orig_h":"({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p":({src_port}\d{1,100})""",
    """"id\.resp_h":"({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p":({dest_port}\d{1,100})""",
    """"share_type":"({share_type}[^"]+)""",
  ]
}
```