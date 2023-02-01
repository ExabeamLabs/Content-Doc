#### Parser Content
```Java
{
Name = symantec-epp-usb-activity-1
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,Commencer :""", """,Type d’action :""", """,ID du périphérique :""", """,Taille de fichier""" ]
    Fields = [
    """SymantecServer:\s({host}[\w\-.]{1,2000})""",
    """(0.0.0.0|({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9]{1,2000}:[A-Fa-f0-9:]{1,2000}))|({src_host}[^\s,]{1,2000})),Bloqués,""",
    """Commencer :\s{1,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Règle : [^,]{0,2000

}
```