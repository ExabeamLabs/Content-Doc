#### Parser Content
```Java
{
Name = tmg-proxy
    Vendor = Microsoft
    Product = Web Application Proxy
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """ UrlDestHost:""", """RawTable:""", """ uri:""" ]
    Fields = [
      """ClientUserName:\s{0,100}"(?:anonymous|({user}[^"]{1,2000}))"""",
      """ClientAgent:\s{0,100}"({user_agent}[^"]{1,2000})"""",
      """logTime:\s{0,100}"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """servername:\s{0,100}"({host}[^"]{1,2000})"""",
      """bytesrecvd:\s{0,100}"({bytes_in}\d{1,100})""",
      """bytessent:\s{0,100}"({bytes_out}\d{1,100})""",
      """transport:\s{0,100}"({protocol}[^"]{1,2000})"""",
      """Action:\s{0,100}"({action}[^"]{1,2000})"""",
      """DecryptedIP:\s{0,100}"({src_ip}[^"]{1,2000})"""",
      """UrlDestHost:\s{0,100}"({web_domain}[^"]{1,2000})"""",
      """DestHostPort:\s{0,100}"({dest_port}[^"]{1,2000})"""",
      """mimetype:\s{0,100}"(?:-|({mime}[^"]{1,2000}))"""",
      """operation:\s{0,100}"(?:-|({method}[^"]{1,2000}))"""",
      """uri:\s{0,100}"(?:-|((\w+:\/+)?[^\/]{1,2000}\/({uri_path}.+?)))(\?|")""",
      """uri:\s{0,100}"(?:-|((\w+:\/+)?[^?]{1,2000}({uri_query}\?.+?)))"""",
    ]
  

}
```