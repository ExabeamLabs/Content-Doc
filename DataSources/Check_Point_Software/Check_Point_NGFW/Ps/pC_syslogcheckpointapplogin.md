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
    """\s({host}[^\s]{1,2000})\s{1,100}product:""",
    """\s({time}\d{1,100}\w{3}\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """;user:\s{1,100}(?:.+?\()({user}[^\)]{1,2000})\)""",
    """;appi_name:\s{1,100}({app}[^;]{1,2000});""",
    """;web_client_type:\s{1,100}(Other: )?({user_agent}.+?)(;\s{0,100}$|;web_server_type:)""",
    """\sdst:\s{1,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssrc:\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]


}
```