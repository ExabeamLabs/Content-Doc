#### Parser Content
```Java
{
Name = bro-web-activity
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"id.orig_h":""", """"id.resp_h":""", """"host":""", """"method":""" ]
  Fields = [
    """exabeam_host=([^@=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"ts":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid":"({conn_id}[^"]{1,2000})""",
    """"id\.orig_h":"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.orig_p":({src_port}\d{1,100})""",
    """"id\.resp_h":"({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.resp_p":({dest_port}[a-fA-F\d.:]{1,2000})""",
    """"host":"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({web_domain}[^\s"]{1,2000}\.[^\s"]{1,2000})|({host}[\w.-]{1,2000}))""",
    """"_system_name":"({host}[^"]{1,2000})""",
    """"uri":"({uri_path}[^"\?]{1,2000}?)\s{0,100}({uri_query}\?[^"]{1,2000}?)?\s{0,100}"""",
    """"user_agent":"\s{0,100}({user_agent}[^:]{1,2000}?)\s{0,100}",""",
    """"status_code":({result_code}\d{1,100})""",
    """"method":"({method}[^"]{1,2000})""",
  ]


}
```