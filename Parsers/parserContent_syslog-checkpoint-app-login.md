#### Parser Content
```Java
{
Name = syslog-checkpoint-app-login
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = [ "product: Application Control;", "appi_name" ]
  Fields = [
    """\s({host}[^\s]+)\s+product:""",
    """\s({time}\d+\w{3}\d+ \d+:\d+:\d+)""",
    """;user:\s+(?:.+?\()({user}[^\)]+)\)""",
    """;appi_name:\s+({app}[^;]+);""",
    """;web_client_type:\s+(Other: )?({user_agent}.+?)(;\s*$|;web_server_type:)""",
    """\sdst:\s+({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssrc:\s+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """;web_client_type:.*?({browser}Trident/7.0|Safari|Firefox|Chrome|Microsoft IE)""",
    """;web_client_type:.*?({os}Windows[^;)]*)""",
    """;web_client_type:.*?Mozilla[^\s]+\s*\(({os}[^\)]+).*({browser}[\d.]+\s+(mobile )?Safari)""",
    """;web_client_type:\s+[^\s]+\s+\(((windows|x11|macintosh|u|compatible);( (u|i);)?\s+)?({os}[^;\)]+).*\s({browser}(Chrome|Firefox)/\d+)""",
    """;web_client_type.*({browser}msie\s+\d[^\s,;\)]+)"""
  ]
}
```