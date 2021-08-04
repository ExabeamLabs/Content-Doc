#### Parser Content
```Java
{
Name = websense-proxy-3
    Vendor = Forcepoint
    Product = Websense Secure Gateway
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """ websense_wsg|v""" ]
    Fields = [
      """({host}[\w.\-]{1,2000})\s{1,100}websense_wsg\|v""",
      """websense_wsg\|([^\^]{1,2000}\^){3}(?:-|({action}[^\^]{1,2000}))\^(?:-|({protocol}[^\^]{1,2000}))\^(?:-|({result_code}[^\^]{1,2000}))\^[^\^]{1,2000}\^(?:-|[^\^]{0,2000}?=(({domain}[^\^\\\/=]{1,2000})[\\\/]{1,2000})?({user}[^\^\\\/=]{1,2000}))\^(?:-|({src_ip}[^\^]{1,2000}))\^(?:-|({src_port}[^\^]{1,2000}))\^(?:-|({dest_ip}[^\^]{1,2000}))\^(?:-|({dest_port}[^\^]{1,2000}))\^(?:-|({web_domain}[^\^]{1,2000}))\^[^\^]{1,2000}\^(?:-|({bytes_out}[^\^]{1,2000}))\^(?:-|({bytes_in}[^\^]{1,2000}))\^([^\^]{1,2000}\^){9}(?:-|({method}[^\^]{1,2000}))\^(?:-|({mime}[^\^]{1,2000}))\^[^\^]{1,2000}\^(?:-|({user_agent}[^\^]{1,2000}))\^[^\^]{1,2000}\^(?:-|({full_url}[^\^]{1,2000}?))\s{0,100}(\^|$)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
      """websense_wsg\|([^\^]{1,2000}\^){12}(?:-|[^\^]{0,2000}?({top_domain}[^\^\.]{1,2000}((?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)))""",
      """websense_wsg\|([^\^]{1,2000}\^){28}(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
      """websense_wsg\|([^\^]{1,2000}\^){30}(?:-|\w+:\/\/[^\/]{1,2000}({uri_path}[^\^\?]{0,2000}?)(\?({uri_query}[^\^]{0,2000}?))?)\s{0,100}(\^|$)"""
    ]
  }
```