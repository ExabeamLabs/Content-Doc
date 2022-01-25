#### Parser Content
```Java
{
Name = json-bro-dhcp-2
  Product = Zeek Network Security Monitor
  DataType = "dhcp"
  Conditions = [ """client_addr":""", """"duration":""", """"msg_types":"""]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"host_name":"({host}[\w.-]{1,2000})""",
    """"client_addr":"({assigned_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
    """"domain":"({domain}[^"]{1,2000})""",
    """"duration":({duration}[^\}]{1,2000})""",
  ]
}
json-bro-activity = {
  Vendor = Zeek
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """exabeam_host=([^@=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"ts\\?"{1,20}:[\[\\]{0,2000}"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})"""
    #""""ts\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid\\?"{1,20}:\\?"{1,20}({conn_id}[^"]{1,2000})""",
    """"id\.orig_h\\?"{1,20}:\\?"{1,20}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.resp_p\\?"{1,20}:({dest_port}\d{1,100})""",
    """"proto\\?"{1,20}:\\?"{1,20}({protocol}[^"]{1,2000})""",
  ]

```