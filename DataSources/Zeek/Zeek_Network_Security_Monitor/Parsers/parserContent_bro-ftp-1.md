#### Parser Content
```Java
{
Name = bro-ftp-1
  Product = Zeek Network Security Monitor
  DataType = "app-activity"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"command":""", """"user""", """"reply_code""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"user":\s{0,100}"((?i)<unknown>|({user}[^"]{1,2000}))""",
    """"password":\s{0,100}"({password}[^"]{1,2000})""",
    """"command":\s{0,100}"({activity}[^"]{1,2000})""",
    """"reply_code":\s{0,100}({trans_id}\d{1,100})""",
    """"reply_msg":\s{0,100}"({additional_info}[^=]{1,2000}?)",""",
    """"data_channel\.resp_p":\s{0,100}({dest_port}\d{1,100})""",
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