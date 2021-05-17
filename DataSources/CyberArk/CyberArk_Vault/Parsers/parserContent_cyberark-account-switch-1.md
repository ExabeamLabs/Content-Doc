#### Parser Content
```Java
{
Name = cyberark-account-switch-1
  Vendor = CyberArk
  Product = CyberArk Vault
  Lms = Direct
  DataType = "account-switch"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """;UsuarioCyberArk="""", """;Accion="Retrieve password"""", """;Safe="""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000})""",
    """;Evento="({event_code}\d{1,100})""",
    """;IP_Origen="({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """;Usuario="({account}[^\s"]{1,2000})""",
    """;IP="({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """;Safe="({safe_value}[^"]{1,2000})""",
    """;GatewayStation="(|({gateway_station}[^"]{1,2000}))""",
    """;UsuarioCyberArk="({user}[^\s"]{1,2000})""",
  ]
}
```