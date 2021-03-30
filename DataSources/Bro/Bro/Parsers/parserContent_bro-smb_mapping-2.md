#### Parser Content
```Java
{
Name = bro-smb_mapping-2
  DataType = "share-access"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"share_type""", """"path""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"path":"({share_path}[^"]+)""",
    """"service":"({service}[^"]+)""",
    """"share_type":"({share_type}[^"]+)""",
  ]
}
json-bro-activity = {
  Vendor = Bro
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """exabeam_host=([^@=]+@\s*)?({host}\S+)""",
    """"ts\\?"+:\\?"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid\\?"+:\\?"+({conn_id}[^"]+)""",
    """"id\.orig_h\\?"+:\\?"+({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"+:({src_port}\d+)""",
    """"id\.resp_h\\?"+:\\?"+({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"+:({dest_port}\d+)""",
    """"proto\\?"+:\\?"+({protocol}[^"]+)""",
  ]

```