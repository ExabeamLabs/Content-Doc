#### Parser Content
```Java
{
Name = paloalto-app-activity-4
  Conditions = [ """|gateway-hip-check|GLOBALPROTECT|""", """GPSourceUser=""" ]
  Fields = ${PaloAltoParserTemplates.paloalto-app-activity.Fields}[
    """({event_name}gateway-hip-check)"""
  ]
  DupFields = [ "event_name->activity" ]

paloalto-app-activity = {
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "MMM dd yyyy HH:mm:ss zzz"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """GPClientHostName =(|({host}[\w.-]{0,2000}?))\s{1,100}\w{1,2000}?=""",
    """rt=({time}\w{3}\s\d{2}\s\d{4}\s(\d{2}:){2}\d{2}\s\S{3})\s""",
    """GPClientPrivateIPv4=({src_translated_ip}[A-Fa-f0-9.:]{1,2000})""",
    """ClientPublicIPv4=({src_ip}[A-Fa-f0-9.:]{1,2000})""",
    """GPSourceUser=(({domain}[^\\\s,]{1,2000})\\+)?({user}[^\\\s,]{1,2000})""",
    """dvchost=({src_host}[\w.-]{1,2000}?)\s""",
    """GPClientOS=(|({os}[^=]{0,2000}?))(\s{1,100})?\w{1,2000}?=""",
    """msg="({additional_info}[^"]{1,2000}?)"""",
    """GPStatus=({outcome}\S{1,2000}?)\s""",
    """({app}GLOBALPROTECT)"""
  
}
```