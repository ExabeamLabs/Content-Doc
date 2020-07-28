#### Parser Content
```Java
{
Name = cisco-adc-web-activity
  Vendor = Cisco
  Product = Cisco ADC
  Lms = Syslog
  DataType = "web-activity"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss"
  Conditions = [ """] """, """ [""", """[ADC_APP]""" ]
  Fields = [
    """\[({host}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\]\[\d+\]\[\S+\]\[\]\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s\[({time}\d+\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d)\s+\+\d+\]\s({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s[\S]*\s\s({dest_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})?\s({dest_translated_port}\d+)?\s"({uri_path}\S+)"\s"({method}\S+)?\s\S*\s({protocol}\S+)?"\s"({full_url}\S+)?"\s"({user_agent}.*)?"""",
    """^([^\s]*\s){18}"(?:-|Mozilla\/.+?\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(X|x)11|(W|w)indows|(L|l)inux|(M|m)acintosh|(D|d)arwin).+?({browser}Chrome|Safari|Opera|(F|f)irefox|MSIE|Trident))""",
    """^([^\s]*\s){18}"(Mozilla.+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """^([^\s]*\s){18}"(?:-|Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d+\s+({browser}\w+))""",
  ]
}
```