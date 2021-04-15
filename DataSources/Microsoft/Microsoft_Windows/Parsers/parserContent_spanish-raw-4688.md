#### Parser Content
```Java
{
Name = spanish-raw-4688
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-process-created"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = ["""Se creó un nuevo proceso""", """Dominio de cuenta:""", """EventCode=4688"""]
  Fields = [
   """Message=({event_name}Se creó un nuevo proceso)""",
   """({event_code}4688)""",
   """\s({host}[^\s]+)\s({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(?i)(AM|PM))""",
   """Firmante creador:\s*Identificador de seguridad:\s*({user_sid}[^\s]+)\s*Nombre de cuenta:\s*({user}[^\s]+)\s*Dominio de cuenta:\s*({domain}[^\s]+)\s*Identificador de inicio de sesión:\s*({logon_id}[^\s]+)""",
   """Nombre del nuevo proceso:\s*(?:|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/\s]+)))\s+Tipo de elevación de token:""",
  ]
}
```