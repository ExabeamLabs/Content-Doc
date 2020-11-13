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
   """\s({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)\s+[^\s]+\s+Skyformation""",
   """exabeam_host=({host}[^\s]+)""",
   """"description":"({additional_info}[^"]+)\"+""",
   """dpriv=({alert_type}[^\s]+)""",
   """"subProvider":"({alert_type}[^"]+)""",
   """"sourceAddress":"({src_ip}[^"]+)""",
   """"accountName":"({user}[^"]+)""",
   """"severity":"({alert_severity}[^"]+)""",
   """"id":"({alert_id}[^"]+)""",  
   """"sourceMaterials":\["({malware_url}[^"]+)""",
   """"protocol":"({protocol}[^"]+)""",
   """"category":"({alert_type}[^"]+)""",
   """"title":"({alert_name}[^"]+)""",
   """"domainName":"({domain}[^"]+)"""",
   """CEF:[^\|]\|([^|]*\|){4}({event_name}[^\|]+)""",
   ] 
}
```