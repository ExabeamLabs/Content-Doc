#### Parser Content
```Java
{
Name = cef-atp-alert-9
  Conditions = [ """CEF""", """|Microsoft|Azure ATP|""", """|DirectoryServicesRogueReplicationSecurityAlert|""" ]

cef-atp-alert = {
  Vendor = Microsoft
  Product = Microsoft Advanced Threat Protection
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """exabeam_host=([^=@]{1,2000}@\s{0,100})?({host}\S+)""",
    """CEF:?([^\|]{0,2000}\|){4}({alert_type}[^\|]{1,2000})\|({alert_name}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})\|""",
    """\WexternalId=({alert_id}\d{1,100})""",
    """\Wstart=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\Wapp=({service}.+?)\s{1,100}(\w+=|$)""",
    """\Wshost=(({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({src_host}[\w\-.]{1,2000}))""",
    """\Wmsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs1=({malware_url}.+?)\s{1,100}(\w+=|$).+?cs1Label=url""",
    """\Wcs1Label=url.*?\Wcs1=({malware_url}.+?)\s{1,100}(\w+=|$)""",
    """\Wsuser=({user}[^\s]{1,2000})\s""",
    """\Wcs2=({outcome}[^\s]{1,2000})""",
    
  
}
```