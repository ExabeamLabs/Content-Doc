#### Parser Content
```Java
{
Name = leef-aruba-nac-logon
  Vendor = HP
  Product = Aruba ClearPass Access Control and Policy Management
  Lms = QRadar
  DataType = "nac-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ssZ"
  Conditions = [ """0|Aruba Networks|ClearPass|""", """Common.NAS-IP-Address=""", """Common.Host-MAC-Address=""" ]
  Fields = [
    """Common\.Request-Timestamp=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d[^\s]{1,2000})""",
    """({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}(LEEF|CEF):""",
    """Common\.Username=(?:({user_type}host)\/)?(({domain}[^\\]{1,2000})\\+)?({user}.*?)(\s\w+\.\w+=)""",
    """Common\.Service=({network}.*?)\s{0,100}([\w\-.]{1,2000}=|$)""",
    """Common\.Host-MAC-Address=({src_mac}\w+)\s{0,100}([\w\-.]{1,2000}=|$)""",
    """Common\.Auth-Type=(|({auth_type}.+?))\s{0,100}([\w\-.]{1,2000}=|$)""",
    """Common\.NAS-IP-Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """AD status:({failure_reason}[^\(]{1,2000})\s""",

  ]
  DupFields = [ "host->auth_server" ]


}
```