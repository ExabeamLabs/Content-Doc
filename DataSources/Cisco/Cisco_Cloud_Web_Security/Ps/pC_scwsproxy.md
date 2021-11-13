#### Parser Content
```Java
{
Name = s-cws-proxy
    Vendor = Cisco
    Product = Cisco Cloud Web Security
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "epoch_sec"
    Conditions = [ """ wbrs-score=""",""" webcat-code="""]
    Fields = [
      """exabeam_host=({host}[\w\-.]{1,2000})""",
      """(Info|CISCOIPORTWSA\-\d{1,100}):\s{1,100}({time}\d{1,100})\.\d{1,100}\s{1,100}\d{1,100}\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}({proxy_action}\w+)\/({result_code}\d{1,100})\s\d{1,100}\s({method}[^\s]{1,2000})\s({full_url}[^\s]{1,2000})""",
      """(Info|CISCOIPORTWSA\-\d{1,100}):\s{1,100}([^\s]{1,2000}\s){6}(?:({protocol}\w+):\/{2}({web_domain}[^:\/]{1,2000})(:\d{1,100})?({uri_path}\/[^?\s]{1,2000})?({uri_query}\?[^\s]{1,2000})?)""",
      """(Info|CISCOIPORTWSA\-\d{1,100}):\s{1,100}([^\s]{1,2000}\s){7}"\w+\\({user}[^@"]{1,2000})(@({domain}[^"]{1,2000}))?"""",
      """(Info|CISCOIPORTWSA\-\d{1,100}):\s{1,100}([^\s]{1,2000}\s){7}("[^"]{1,2000}"|\-)\s([^\s]{1,2000}\s)(?:-|({mime}[^\s]{1,2000}))\s(?:-|({action}[^\-\s]{1,2000}))""",
      """\ss-ip=\s{1,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ss-port=\s{1,100}({dest_port}\d{1,100})""",
      """\swebcat-code=\s{1,100}"({category}[^"]{1,2000})"""",
      """\scs-bytes=\s{1,100}({bytes_out}\d{1,100})""",
      """\ssc-bytes=\s{1,100}({bytes_in}\d{1,100})""",
      """\scs-user-agent=\s{1,100}"(?:-|({user_agent}[^"]{1,2000}))"""",
    ]
  

}
```