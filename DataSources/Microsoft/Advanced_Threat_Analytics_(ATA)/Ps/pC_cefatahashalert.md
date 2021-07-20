#### Parser Content
```Java
{
Name = cef-ata-hash-alert
  Vendor = Microsoft
  Product = Advanced Threat Analytics (ATA)
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """|Microsoft|ATA|""", """|PassTheHashSuspiciousActivity|""" ]
  Fields = [
    """exabeam_host=([^=@]{1,2000}@)?({host}[\w.\-]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){4}({alert_type}[^\|]{1,2000})\|({alert_name}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})\|""",
    """\WexternalId=({alert_id}\d{1,100})""",
    """\Wstart=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\Wsuser=(?:(({user_lastname}[\w\']{1,2000}), ({user_firstname}\w+))|({user}[^\s]{1,2000}))\s{1,100}(\w+=|$)""",
    """\Wapp=({service}.+?)\s{1,100}(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """\Wmsg=[^=]{1,2000}? used from (?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w.\-]{1,2000}\w))""",
    """\Wshost=(?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w.\-]{1,2000}))\s{1,100}(\w+=|$)""",
  ]
}
```