#### Parser Content
```Java
{
Name = json-zeek-kerberos
  Product = Zeek Network Security Monitor
  DataType = "remote-access"
  Conditions = [ """ zeek_kerberos """, """"id.orig_h""", """"id.resp_h""" ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"client\\?"{1,20}:\\?"{1,20}({user}[^"\\]{1,2000})""",
    """"request_type\\?"{1,20}:\\?"{1,20}({request_type}[^"\\]{1,2000})""",
    """"client\\?"{1,20}:\\?"{1,20}({user}[^"\/\\]{1,2000})(\/({domain}[^"\\]{1,2000}))?""",
    """"service\\?"{1,20}:\\?"{1,20}({service_name}[^"\/\\@]{1,2000})""",
    """"success\\?"{1,20}:({outcome}\w+)""",
    """"cipher\\?"{1,20}:\\?"{1,20}({ticket_encryption_type}[^"\\]{1,2000})"""
  ]

json-zeek-activity = {
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Splunk
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^@=]{1,2000}@\s{0,100})?({host}\S{1,2000})""",
    """"_system_name":"({host}[\w\-.]{1,2000})"""",
    """"ts"{1,20}:({time}\d{1,100})""",
    """"uid\\?"{1,20}:\\?"{1,20}({conn_id}[^"\\]{1,2000})""",
    """"id\.orig_h\\?"{1,20}:\\?"{1,20}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.resp_p\\?"{1,20}:({dest_port}[a-fA-F\d.:]{1,2000})""",
  
}
```