#### Parser Content
```Java
{
Name = digital-web-activity
    Vendor = Digital Arts
    Product = Digital Arts i-FILTER for Business
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
    Conditions = [ """Digital Arts""", """i-FILTER Proxy Server""" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """\w+ \d{1,100} \d\d:\d\d:\d\d \d{1,100} \S+ (-|({dest_ip}[A-Fa-f:\d.]{1,2000})) (-|({src_ip}[A-Fa-f:\d.]{1,2000})) (-|({src_host}\S+)) (-|({user}[^\s]{1,2000})) \[({time}\d{1,100}\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d [+-]\d{1,100})\] ({result_code}\d{1,100}) ({bytes_out}\d{1,100}) ({bytes_in}\d{1,100}) ({action}\S+) ({reason}\S+) ({category}\S+)[^"]{1,2000}?"{1,20}({method}\S+) ({full_url}(({protocol}\w+):[\\\/]{1,2000})?({web_domain}[^\\\/\s:]{1,2000})({uri_path}\/[^\s\?]{1,2000})?({uri_query}\?[^\s"]{1,2000})?)[^"]{0,2000}"{1,20} (-|({referrer}\S+)) (-|({user_agent}[^"]{1,2000}?)) \S+ \S+\s{1,100}$""",
      """({top_domain}[^\\\/\s."]{1,2000}(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)(:|\/|\s)""",
      """(Mozilla.+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    ]
  

}
```