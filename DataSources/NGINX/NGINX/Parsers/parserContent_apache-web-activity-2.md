#### Parser Content
```Java
{
Name = apache-web-activity-2
  Vendor = NGINX
  Product = NGINX
  Conditions = [ """ nginx: """, """ HTTP/1.""", """] """" ]
  Fields = ${ApacheParserTemplates.apache-web-activity.Fields}[
    """({host}[\w\-.]+)\s+nginx:""",
  ]
}
apache-web-activity = {
  Vendor = Apache
  Product = Apache
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """(?:-|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}\S+))\s+(\S+\s+){2}\[({time}\d\d\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d)\s+(?:\+|\-)\d+\]\s+"({method}\w+)\s+({uri_path}[^"\?\s]+)(?:\?({uri_query}[^?\s]+))?.*?"\s+({result_code}\d+)\s+(-|({bytes_out}\d+))\s+"(?:-|({referrer}[^"]+))"\s+"?(-|({user_agent}[^"]+?))("|\s*$)""",
    """Mozilla\/[^"]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """Mozilla\/[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)"""
  ]

```