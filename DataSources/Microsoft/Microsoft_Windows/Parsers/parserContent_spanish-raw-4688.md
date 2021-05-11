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
   """Firmante creador:\s{0,100}Identificador de seguridad:\s{0,100}({user_sid}[^\s]+)\s{0,100}Nombre de cuenta:\s{0,100}({user}[^\s]+)\s{0,100}Dominio de cuenta:\s{0,100}({domain}[^\s]+)\s{0,100}Identificador de inicio de sesión:\s{0,100}({logon_id}[^\s]+)""",
   """Nombre del nuevo proceso:\s{0,100}(?:|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/\s]+)))\s{1,100}Tipo de elevación de token:""",
  ]
}
```