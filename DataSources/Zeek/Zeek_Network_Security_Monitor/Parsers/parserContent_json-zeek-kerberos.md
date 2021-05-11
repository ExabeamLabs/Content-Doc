#### Parser Content
```Java
{
Name = json-zeek-kerberos
  Product = Zeek Network Security Monitor
  DataType = "remote-access"
  Conditions = [ """ zeek_kerberos """, """"id.orig_h""", """"id.resp_h""" ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"client\\?"{1,20}:\\?"{1,20}({user}[^"\\]+)""",
    """"request_type\\?"{1,20}:\\?"{1,20}({request_type}[^"\\]+)""",
    """"client\\?"{1,20}:\\?"{1,20}({user}[^"\/\\]+)(\/({domain}[^"\\]+))?""",
    """"service\\?"{1,20}:\\?"{1,20}({service_name}[^"\/\\@]+)""",
    """"success\\?"{1,20}:({outcome}\w+)""",
    """"cipher\\?"{1,20}:\\?"{1,20}({ticket_encryption_type}[^"\\]+)"""
  ]
}
json-zeek-activity = {
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Splunk
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^@=]+@\s{0,100})?({host}\S+)""",
    """"ts"{1,20}:({time}\d{1,100})""",
    """"uid\\?"{1,20}:\\?"{1,20}({conn_id}[^"\\]+)""",
    """"id\.orig_h\\?"{1,20}:\\?"{1,20}({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"{1,20}:({dest_port}[a-fA-F\d.:]+)""",
  ]

```