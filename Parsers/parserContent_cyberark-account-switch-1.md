#### Parser Content
```Java
{
Name = cyberark-account-switch-1
  Vendor = CyberArk Vault
  Product = CyberArk Vault
  Lms = Direct
  DataType = "account-switch"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """;UsuarioCyberArk="""", """;Accion="Retrieve password"""", """;Safe="""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s+\d+\s+\d\d:\d\d:\d\d ({host}[\w\-.]+)""",
    """;Evento="({event_code}\d+)""",
    """;IP_Origen="({src_ip}[A-Fa-f:\d.]+)""",
    """;Usuario="({account}[^\s"]+)""",
    """;IP="({dest_ip}[A-Fa-f:\d.]+)""",
    """;Safe="({safe_value}[^"]+)""",
    """;GatewayStation="(|({gateway_station}[^"]+))""",
    """;UsuarioCyberArk="({user}[^\s"]+)""",
  ]
}
```