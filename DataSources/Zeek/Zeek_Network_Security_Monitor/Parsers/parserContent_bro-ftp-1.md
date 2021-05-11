#### Parser Content
```Java
{
Name = bro-ftp-1
  Product = Zeek Network Security Monitor
  DataType = "app-activity"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"command":""", """"user""", """"reply_code""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"user":\s{0,100}"((?i)<unknown>|({user}[^"]+))""",
    """"password":\s{0,100}"({password}[^"]+)""",
    """"command":\s{0,100}"({activity}[^"]+)""",
    """"reply_code":\s{0,100}({trans_id}\d{1,100})""",
    """"reply_msg":\s{0,100}"({additional_info}[^=]+?)",""",
    """"data_channel\.resp_p":\s{0,100}({dest_port}\d{1,100})""",
  ]
}
json-bro-activity = {
  Vendor = Zeek
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """exabeam_host=([^@=]+@\s{0,100})?({host}\S+)""",
    """"ts\\?"{1,20}:[\[\\]*"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})"""
    #""""ts\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid\\?"{1,20}:\\?"{1,20}({conn_id}[^"]+)""",
    """"id\.orig_h\\?"{1,20}:\\?"{1,20}({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"{1,20}:({dest_port}\d{1,100})""",
    """"proto\\?"{1,20}:\\?"{1,20}({protocol}[^"]+)""",
  ]

```