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
   """\s({host}[^\s]{1,2000})\s({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(?i)(AM|PM))""",
   """Firmante creador:\s{0,100}Identificador de seguridad:\s{0,100}({user_sid}[^\s]{1,2000})\s{0,100}Nombre de cuenta:\s{0,100}({user}[^\s]{1,2000})\s{0,100}Dominio de cuenta:\s{0,100}({domain}[^\s]{1,2000})\s{0,100}Identificador de inicio de sesión:\s{0,100}({logon_id}[^\s]{1,2000})""",
   """Nombre del nuevo proceso:\s{0,100}(?:|({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/\s]{1,2000})))\s{1,100}Tipo de elevación de token:""",
  ]
}
```