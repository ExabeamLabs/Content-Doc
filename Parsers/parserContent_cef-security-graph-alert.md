#### Parser Content
```Java
{
Name = cef-security-graph-alert
 Vendor = Microsoft
 Product = Microsoft Graph
 Lms = Directory
 DataType = "alert"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
 Conditions = [ """CEF:""", """|sk4-security-threat-detected|security-threat-detected|""", """dproc=Graph Security Alerts"""]
 Fields = [
   """\s({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)\s+({host}[^\s]+)\s+Skyformation""",
   """"+description"+:"+({additional_info}[^"]+)\"+""",
   """dpriv=({alert_type}.+?)\s\w+=""",
   """"+subProvider"+:"+({alert_type}[^"]+)""",
   """"+sourceAddress"+:"+({src_ip}[^"]+)""",
   """"+accountName"+:"+({user}[^"]+)""",
   """"+severity"+:"+({alert_severity}[^"]+)""",
   """"+id"+:"+({alert_id}[^"]+)""",  
   """"+severity"+.+?sourceMaterials"+:\["+({malware_url}[^"]+)""",
   """"+protocol"+:"+({protocol}[^"]+)""",
   """"category":"({category}[^"]+)""",
   """"title":"({alert_name}[^"]+)"""
   ] 
}
```