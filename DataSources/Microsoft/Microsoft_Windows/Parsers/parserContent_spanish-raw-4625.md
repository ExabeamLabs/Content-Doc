#### Parser Content
```Java
{
Name = spanish-raw-4625
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-failed-logon"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = ["""Error de una cuenta al iniciar sesión""", """Nombre de cuenta:""", """EventCode=4625"""]
  Fields = [
   """Message=({event_name}Error de una cuenta al iniciar sesión)""",
   """({event_code}4625)""",
   """\s({host}[^\s]+)\s({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(?i)(AM|PM))""",
   """Sujeto:[^=]+?\s*Nombre de cuenta:\s*(-|({caller_user}[^\s@]+?))[\s;]*Dominio de cuenta""",
   """Sujeto:[^=]+?\s*Dominio de cuenta:\s*(-|({caller_domain}[^:;]+?))[\s;]*Id. de inicio de sesión:""",
   """Tipo de inicio de sesión:\s*({logon_type}\d+)""",
   """Cuenta con error de inicio de sesión:\s*[^=]+\s*Id. de seguridad:\s*(?:\/?NULL SID|({user_sid}[^\s]+))\s*Nombre de cuenta:""",
   """Nombre de cuenta:\s*({user}[^\s]+)\s*Dominio de cuenta:\s*({domain}[^\s]+)\s*Información de error:""",
   """Estado:\s*(?:[^\s]+)\s*Subestado:\s*({result_code}[^\s]+)\s*Información de proceso:""",
   """Nombre de estación de trabajo:\s*({src_host}[^\s]+)\s*Dirección de red de origen:\s*({src_ip}[a-fA-F\d.:]+)\s*Puerto de orig""",
  ]
  DupFields = ["host->dest_host"]
}
```