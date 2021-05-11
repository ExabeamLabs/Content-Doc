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
      """({host}[\w.\-]+)\s{1,100}websense_wsg\|v""",
      """websense_wsg\|([^\^]+\^){3}(?:-|({action}[^\^]+))\^(?:-|({protocol}[^\^]+))\^(?:-|({result_code}[^\^]+))\^[^\^]+\^(?:-|[^\^]*?=(({domain}[^\^\\\/=]+)[\\\/]+)?({user}[^\^\\\/=]+))\^(?:-|({src_ip}[^\^]+))\^(?:-|({src_port}[^\^]+))\^(?:-|({dest_ip}[^\^]+))\^(?:-|({dest_port}[^\^]+))\^(?:-|({web_domain}[^\^]+))\^[^\^]+\^(?:-|({bytes_out}[^\^]+))\^(?:-|({bytes_in}[^\^]+))\^([^\^]+\^){9}(?:-|({method}[^\^]+))\^(?:-|({mime}[^\^]+))\^[^\^]+\^(?:-|({user_agent}[^\^]+))\^[^\^]+\^(?:-|({full_url}[^\^]+?))\s{0,100}(\^|$)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
      """websense_wsg\|([^\^]+\^){12}(?:-|[^\^]*?({top_domain}[^\^\.]+((?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)))""",
      """websense_wsg\|([^\^]+\^){28}(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
      """websense_wsg\|([^\^]+\^){30}(?:-|\w+:\/\/[^\/]+({uri_path}[^\^\?]*?)(\?({uri_query}[^\^]*?))?)\s{0,100}(\^|$)"""
    ]
  }
```