#### Parser Content
```Java
{
Name = syslog-checkpoint-app-login-1
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = [ """CP_FireWall:""", "ProductName: Application Control;", "appi_name" ]
  Fields = [
    """CP_FireWall:\s+({time}\d+\w{3}\d+\s+\d+:\d+:\d+)(\s+\S+){4}\s+({host}[^\s]+)""",
    """;\s*appi_name:\s+({app}[^;]+);""",
    """;\s*web_client_type:\s+(Other: )?({user_agent}.+?);\s*($|web_server_type:)""",
    """\sdst:\s+({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssrc:\s+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """;\s*web_client_type:.*?({browser}Trident/7.0|Safari|Firefox|Chrome|Microsoft IE)""",
    """;\s*web_client_type:.*?({os}Windows[^;)]*)""",
    """;\s*web_client_type:.*?Mozilla[^\s]+\s*\(({os}[^\)]+).*({browser}[\d.]+\s+(mobile )?Safari)""",
    """;\s*web_client_type:\s+[^\s]+\s+\(((windows|x11|macintosh|u|compatible);( (u|i);)?\s+)?({os}[^;\)]+).*\s({browser}(Chrome|Firefox)/\d+)""",
    """;\s*web_client_type.*({browser}msie\s+\d[^\s,;\)]+)"""
  ]
}
```