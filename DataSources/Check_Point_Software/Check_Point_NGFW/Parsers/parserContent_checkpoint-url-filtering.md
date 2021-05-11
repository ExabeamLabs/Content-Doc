#### Parser Content
```Java
{
Name = checkpoint-url-filtering
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = ["""Product=URL Filtering""" , """Action=""", """rule_name=""" ]
  Fields = [
    """"({time}\d\d\w{3}\d\d\d\d\s\d\d:\d\d:\d\d)""",
    """Origin=({host}[^|\s]+)""",
    """URL=(?:-|({url}[^|\s]+))""",
    """User=({user}[^|]+)\s""",
    """src_user_name=(|-|(({first_name}[^\s]+)\s({last_name}[^\s]+)\s\(({user}[^\)]+)))\)\s{0,100}\|"""
    """Action=(?:-|({action}[^|\s]+))""",
    """client_type_os=(?:-|({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """connection_count=(?:-|({count}\d{1,100}))""",
    """\|rule_name=(?:-|({rule}[^|]+))""",
    """\|SIP=(?:-|({src_ip}[A-Fa-f:\d.]+))""",  
    """\|DIP=(?:-|({dest_ip}[A-Fa-f:\d.]+))""",
    """\|SPort=(?:-|({src_port}\d{1,100}))""",
    """\|DPort=(?:-|({dest_port}\d{1,100}))""",
    """web_client_type.+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident|Internet Explorer)""",
    """Protocol=(?:-|({protocol}[^|\s]+))""",
    """IFDirection=(?:-|({direction}[^|\s]+))""",
    """Source=(?:[-\d.]+|({src_host}[^|\s]+))""",
    """Destination=(?:[-\d.]+|({dest_host}[^|\s]+))""",
    """XlateSIP=(?:-|({src_translated_ip}[A-Fa-f:\d.]+))""",
    """XlateDIP=(?:-|({dest_translated_ip}[A-Fa-f:\d.]+))""",
    """XlateDPort=(?:-|({dest_translated_port}\d{1,100}))""",
    """XlateSport=(?:-|({src_translated_port}\d{1,100}))""",
 ]
}
```