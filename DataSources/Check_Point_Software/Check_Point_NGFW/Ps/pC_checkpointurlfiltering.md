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
    """Origin=({host}[^|\s]{1,2000})""",
    """URL=(?:-|({url}[^|\s]{1,2000}))""",
    """User=({user}[^|]{1,2000})\s""",
    """src_user_name=(|-|(({first_name}[^\s]{1,2000})\s({last_name}[^\s]{1,2000})\s\(({user}[^\)]{1,2000})))\)\s{0,100}\|"""
    """Action=(?:-|({action}[^|\s]{1,2000}))""",
    """client_type_os=(?:-|({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """connection_count=(?:-|({count}\d{1,100}))""",
    """\|rule_name=(?:-|({rule}[^|]{1,2000}))""",
    """\|SIP=(?:-|({src_ip}[A-Fa-f:\d.]{1,2000}))""",  
    """\|DIP=(?:-|({dest_ip}[A-Fa-f:\d.]{1,2000}))""",
    """\|SPort=(?:-|({src_port}\d{1,100}))""",
    """\|DPort=(?:-|({dest_port}\d{1,100}))""",
    """web_client_type=({user_agent}[^|\s]{1,2000})""",
    """Protocol=(?:-|({protocol}[^|\s]{1,2000}))""",
    """IFDirection=(?:-|({direction}[^|\s]{1,2000}))""",
    """Source=(?:[-\d.]{1,2000}|({src_host}[^|\s]{1,2000}))""",
    """Destination=(?:[-\d.]{1,2000}|({dest_host}[^|\s]{1,2000}))""",
    """XlateSIP=(?:-|({src_translated_ip}[A-Fa-f:\d.]{1,2000}))""",
    """XlateDIP=(?:-|({dest_translated_ip}[A-Fa-f:\d.]{1,2000}))""",
    """XlateDPort=(?:-|({dest_translated_port}\d{1,100}))""",
    """XlateSport=(?:-|({src_translated_port}\d{1,100}))""",
 ]


}
```