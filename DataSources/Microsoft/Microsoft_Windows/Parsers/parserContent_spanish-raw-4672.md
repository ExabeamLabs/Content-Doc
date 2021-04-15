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
   """\s({host}[^\s]+)\s({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(?i)(AM|PM))""",
   """Keywords=({outcome}[^=]+?)\s*TaskCategory=""",
   """Nombre de cuenta:\s*(-|SYSTEM|({user}[^\s]+))\s*Dominio de cuenta:\s*({domain}[^\s]+)\s*""",
   """Id. de inicio de sesión:\s*({logon_id}[^\s]+)\s*Privilegios:\s*({privileges}[^\:]+?)?\s*$""",
  ]
  DupFields = ["host->dest_host"]
}
```