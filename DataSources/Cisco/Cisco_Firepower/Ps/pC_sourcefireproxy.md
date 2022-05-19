#### Parser Content
```Java
{
Name = sourcefire-proxy
    Vendor = Cisco
    Product = Cisco Firepower
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """SFIMS""", """Policy: Default Access Control""", """ApplicationProtocol: HTTP""" ]
    Fields = [
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """SrcIP:\s{0,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """DstIP:\s{0,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """SrcPort:\s{0,100}({src_port}\d{1,100})""",
      """DstPort:\s{0,100}({dest_port}\d{1,100})""",
      """AccessControlRuleAction:\s{0,100}({action}[^,]{1,2000})""",
      """UserName:\s{0,100}({user}[^,]{1,2000})""",
      """Client:\s{0,100}({user_agent}[^,]{1,2000})""",
      """UserAgent:\s{0,100}({user_agent}.+?),\s{0,100}Client:""",
      """ApplicationProtocol:\s{0,100}({protocol}[^,]{1,2000})""",
      """InitiatorBytes:\s{0,100}({bytes_out}[^,]{1,2000})""",
      """ResponderBytes:\s{0,100}({bytes_in}[^,]{1,2000})""",
      """URLCategory:\s{0,100}({category}[^,]{1,2000})""",
      """URL:\s{0,100}({full_url}\S+?)(,\s{0,100}\w+:|\s)""",
      """URL:\s{0,100}(?:-|\w+:\/+)({web_domain}[^\s\/]{1,2000})""",
      """URL:\s{0,100}(?:-|\w+:\/+[^\/]{1,2000})({uri_path}\/[^?\s]{1,2000})""",
      """URL:\s{0,100}.*?({uri_query}\?[^\s"]{1,2000})""",
    ]
  

}
```