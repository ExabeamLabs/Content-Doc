#### Parser Content
```Java
{
Name = json-zeek_ntlm
  Product = Zeek Network Security Monitor
  DataType = "ntlm-logon"
  Conditions = [ """ zeek_ntlm """, """"id.orig_h""", """"id.resp_h""" ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"server_nb_computer_name"{1,20}:"{1,20}({sub_domain}[^"]+)""",
    """"server_dns_computer_name"{1,20}:"{1,20}({dns_domain}[^"]+)""",
    """"server_tree_name"{1,20}:"{1,20}({domain}[^"]+)"""
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