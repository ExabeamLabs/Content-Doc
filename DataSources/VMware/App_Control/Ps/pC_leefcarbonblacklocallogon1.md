#### Parser Content
```Java
{
Name = leef-carbonblack-local-logon-1
  DataType = "local-logon"
  Conditions = [ """LEEF:""", """|Carbon_Black|Protection|""", """Event[00000005] Type[SessionLogon]""" ]

leef-carbonblack-events = {
  Vendor = VMware
  Product = App Control
  Lms = QRadar
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({host}[\w\-.]{1,2000})\s{1,100}LEEF:""",
    """\WdevTime=({time}\w+\s{1,100}\d{1,100}\s{1,100}\d\d\d\d\s{1,100}\d\d:\d\d:\d\d\.\d{1,100} \w+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\WsrcHostName =(({domain}[^\\\s]{1,2000})\\+)?({src_host}[\w\-.]{1,2000})""",
    """\WdstHostName =({dest_host}[\w\-.]{1,2000})""",
    """\WEvent\[({event_code}\d{1,100})\]\s{0,100}Type\[""",
    """\WUser\[(({domain}[^\\\s\]]{1,2000})\\+)?(|({user}[^\\\s\]]{1,2000}))\]""",
  
}
```