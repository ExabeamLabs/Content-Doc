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
```