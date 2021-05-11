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
    """\s({host}[^\s]+)\s{1,100}product:""",
    """\s({time}\d{1,100}\w{3}\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """;user:\s{1,100}(?:.+?\()({user}[^\)]+)\)""",
    """;appi_name:\s{1,100}({app}[^;]+);""",
    """;web_client_type:\s{1,100}(Other: )?({user_agent}.+?)(;\s{0,100}$|;web_server_type:)""",
    """\sdst:\s{1,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssrc:\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """;web_client_type:.*?({browser}Trident/7.0|Safari|Firefox|Chrome|Microsoft IE)""",
    """;web_client_type:.*?({os}Windows[^;)]*)""",
    """;web_client_type:.*?Mozilla[^\s]+\s{0,100}\(({os}[^\)]+).*({browser}[\d.]+\s{1,100}(mobile )?Safari)""",
    """;web_client_type:\s{1,100}[^\s]+\s{1,100}\(((windows|x11|macintosh|u|compatible);( (u|i);)?\s{1,100})?({os}[^;\)]+).*\s({browser}(Chrome|Firefox)/\d{1,100})""",
    """;web_client_type.*({browser}msie\s{1,100}\d[^\s,;\)]+)"""
  ]
}
```