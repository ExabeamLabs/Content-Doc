#### Parser Content
```Java
{
Name = spanish-raw-4672
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-privileged-access"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = ["""Se asignaron privilegios especiales a un nuevo inicio de sesión""", """Nombre de cuenta:""", """EventCode=4672"""]
  Fields = [
   """Message=({event_name}Se asignaron privilegios especiales a un nuevo inicio de sesión)""",
   """({event_code}4672)""",
   """\s({host}[^\s]{1,2000})\s({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(?i)(AM|PM))""",
   """Keywords=({outcome}[^=]{1,2000}?)\s{0,100}TaskCategory=""",
   """Nombre de cuenta:\s{0,100}(-|SYSTEM|({user}[^\s]{1,2000}))\s{0,100}Dominio de cuenta:\s{0,100}({domain}[^\s]{1,2000})\s{0,100}""",
   """Id. de inicio de sesión:\s{0,100}({logon_id}[^\s]{1,2000})\s{0,100}Privilegios:\s{0,100}({privileges}[^\:]{1,2000}?)?\s{0,100}$""",
  ]
  DupFields = ["host->dest_host"]
}
```