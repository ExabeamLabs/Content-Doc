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
   """\s({host}[^\s]{1,2000})\s({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(?i)(AM|PM))""",
   """Sujeto:[^=]{1,2000}?\s{0,100}Nombre de cuenta:\s{0,100}(-|({caller_user}[^\s@]{1,2000}?))[\s;]{0,2000}Dominio de cuenta""",
   """Sujeto:[^=]{1,2000}?\s{0,100}Dominio de cuenta:\s{0,100}(-|({caller_domain}[^:;]{1,2000}?))[\s;]{0,2000}Id. de inicio de sesión:""",
   """Tipo de inicio de sesión:\s{0,100}({logon_type}\d{1,100})""",
   """Cuenta con error de inicio de sesión:\s{0,100}[^=]{1,2000}\s{0,100}Id. de seguridad:\s{0,100}(?:\/?NULL SID|({user_sid}[^\s]{1,2000}))\s{0,100}Nombre de cuenta:""",
   """Nombre de cuenta:\s{0,100}({user}[^\s]{1,2000})\s{0,100}Dominio de cuenta:\s{0,100}({domain}[^\s]{1,2000})\s{0,100}Información de error:""",
   """Estado:\s{0,100}(?:[^\s]{1,2000})\s{0,100}Subestado:\s{0,100}({result_code}[^\s]{1,2000})\s{0,100}Información de proceso:""",
   """Nombre de estación de trabajo:\s{0,100}({src_host}[^\s]{1,2000})\s{0,100}Dirección de red de origen:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})\s{0,100}Puerto de orig""",
  ]
  DupFields = ["host->dest_host"]
}
```