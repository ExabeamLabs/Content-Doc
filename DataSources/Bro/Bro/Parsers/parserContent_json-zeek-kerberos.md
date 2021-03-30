#### Parser Content
```Java
{
Name = json-zeek-kerberos
  DataType = "remote-access"
  Conditions = [ """ zeek_kerberos """, """"id.orig_h""", """"id.resp_h""" ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"client\\?"+:\\?"+({user}[^"\\]+)""",
    """"request_type\\?"+:\\?"+({request_type}[^"\\]+)""",
    """"client\\?"+:\\?"+({user}[^"\/\\]+)(\/({domain}[^"\\]+))?""",
    """"service\\?"+:\\?"+({service_name}[^"\/\\@]+)""",
    """"success\\?"+:({outcome}\w+)""",
    """"cipher\\?"+:\\?"+({ticket_encryption_type}[^"\\]+)"""
  ]
}
json-zeek-activity = {
  Vendor = Bro
  Product = Bro
  Lms = Splunk
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^@=]+@\s*)?({host}\S+)""",
    """"ts"+:({time}\d+)""",
    """"uid\\?"+:\\?"+({conn_id}[^"\\]+)""",
    """"id\.orig_h\\?"+:\\?"+({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"+:({src_port}\d+)""",
    """"id\.resp_h\\?"+:\\?"+({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"+:({dest_port}[a-fA-F\d.:]+)""",
  ]

```