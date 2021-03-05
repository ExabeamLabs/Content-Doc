#### Parser Content
```Java
{
Name = netscaler-web-activity
    Vendor = Citrix Netscaler
    Product = Web Logging
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """<cont-5991 conditions>""" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s+(?:-|({host}\S+))\s+(?:-|({user}\S+))\s+(?:-|({protocol}\S+))\s+(?:-|({src_ip}\S+))\s+(?:-|({src_port}\S+))\s+(?:-|({method}\S+))\s+(?:-|({uri_path}\S+))\s+(?:-|({uri_query}\S+))\s+(?:-|({result_code}\S+))\s+(?:-|({bytes_in}\S+))\s+(?:-|({bytes_out}\S+))\s+(\S+\s+){2}(?:-|({user_agent}\S+))\s+\S+\s+(?:-|({referrer}\S+))\s*$""",
      """Mozilla\/[^\s]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^\s]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)"""
    ]
  }
```