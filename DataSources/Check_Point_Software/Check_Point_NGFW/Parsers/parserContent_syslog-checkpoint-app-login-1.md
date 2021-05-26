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
    """CP_FireWall:\s{1,100}({time}\d{1,100}\w{3}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})(\s{1,100}\S+){4}\s{1,100}({host}[^\s]{1,2000})""",
    """;\s{0,100}appi_name:\s{1,100}({app}[^;]{1,2000});""",
    """;\s{0,100}web_client_type:\s{1,100}(Other: )?({user_agent}.+?);\s{0,100}($|web_server_type:)""",
    """\sdst:\s{1,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssrc:\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """;\s{0,100}web_client_type:.*?({browser}Trident/7.0|Safari|Firefox|Chrome|Microsoft IE)""",
    """;\s{0,100}web_client_type:.*?({os}Windows[^;)]{0,2000})""",
    """;\s{0,100}web_client_type:.*?Mozilla[^\s]{1,2000}\s{0,100}\(({os}[^\)]{1,2000}).*({browser}[\d.]{1,2000}\s{1,100}(mobile )?Safari)""",
    """;\s{0,100}web_client_type:\s{1,100}[^\s]{1,2000}\s{1,100}\(((windows|x11|macintosh|u|compatible);( (u|i);)?\s{1,100})?({os}[^;\)]{1,2000}).*\s({browser}(Chrome|Firefox)/\d{1,100})""",
    """;\s{0,100}web_client_type.*({browser}msie\s{1,100}\d[^\s,;\)]{1,2000})"""
  ]
}
```