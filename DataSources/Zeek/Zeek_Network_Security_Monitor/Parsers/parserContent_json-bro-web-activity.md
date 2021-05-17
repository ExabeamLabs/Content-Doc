#### Parser Content
```Java
{
Name = json-bro-web-activity
  Product = Zeek Network Security Monitor
  DataType = "web-activity"
  Conditions = [ """"status_code":""",  """"trans_depth":""", """"id.resp_h":""",""""resp_mime_types"""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"_system_name":"({host}[^"]{1,2000})""",
    """"status_code":({result_code}\d{1,100})""",
    """"resp_mime_types":\["({mime}[^"]{1,2000})""",
    """"resp_fuids":\["({file_id}[^"]{1,2000})""",
    """"status_msg":"({additional_info}[^"]{1,2000})""",
    """"method":"({method}[^"]{1,2000})""",
    """"uri":"({uri_path}[^"\?]{1,2000}?)\s{0,100}({uri_query}\?[^"]{1,2000}?)?\s{0,100}"""",
    """"user_agent":"\s{0,100}({user_agent}[^"]{1,2000}?)\s{0,100}"""",

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