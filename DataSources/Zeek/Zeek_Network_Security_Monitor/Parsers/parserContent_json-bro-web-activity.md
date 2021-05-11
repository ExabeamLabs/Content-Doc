#### Parser Content
```Java
{
Name = json-bro-web-activity
  Product = Zeek Network Security Monitor
  DataType = "web-activity"
  Conditions = [ """"status_code":""",  """"trans_depth":""", """"id.resp_h":""",""""resp_mime_types"""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"_system_name":"({host}[^"]+)""",
    """"status_code":({result_code}\d{1,100})""",
    """"resp_mime_types":\["({mime}[^"]+)""",
    """"resp_fuids":\["({file_id}[^"]+)""",
    """"status_msg":"({additional_info}[^"]+)""",
    """"method":"({method}[^"]+)""",
    """"uri":"({uri_path}[^"\?]+?)\s{0,100}({uri_query}\?[^"]+?)?\s{0,100}"""",
    """"user_agent":"\s{0,100}({user_agent}[^"]+?)\s{0,100}"""",

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