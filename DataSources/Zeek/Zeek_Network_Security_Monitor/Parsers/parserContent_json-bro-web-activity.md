#### Parser Content
```Java
{
Name = json-bro-web-activity
  Product = Zeek Network Security Monitor
  DataType = "web-activity"
  Conditions = [ """"status_code":""",  """"trans_depth":""", """"id.resp_h":""",""""resp_mime_types"""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"_system_name":"({host}[^"]+)""",
    """"status_code":({result_code}\d+)""",
    """"resp_mime_types":\["({mime}[^"]+)""",
    """"resp_fuids":\["({file_id}[^"]+)""",
    """"status_msg":"({additional_info}[^"]+)""",
    """"method":"({method}[^"]+)""",
    """"uri":"({uri_path}[^"\?]+?)\s*({uri_query}\?[^"]+?)?\s*"""",
    """"user_agent":"\s*({user_agent}[^"]+?)\s*"""",

  ]
}
json-bro-activity = {
  Vendor = Zeek
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """exabeam_host=([^@=]+@\s*)?({host}\S+)""",
    """"ts\\?"+:[\[\\]*"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})"""
    #""""ts\\?"+:\\?"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid\\?"+:\\?"+({conn_id}[^"]+)""",
    """"id\.orig_h\\?"+:\\?"+({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"+:({src_port}\d+)""",
    """"id\.resp_h\\?"+:\\?"+({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"+:({dest_port}\d+)""",
    """"proto\\?"+:\\?"+({protocol}[^"]+)""",
  ]

```