#### Parser Content
```Java
{
Name = cef-ata-forgedpac-alert
  Vendor = Microsoft
  Product = Advanced Threat Analytics (ATA)
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """|Microsoft|ATA|""", """|ForgedPacSuspiciousActivity|""" ]
  Fields = [
    """exabeam_host=([^=@]+@)?({host}[\w.\-]+)""",
    """CEF:([^\|]*\|){4}({alert_type}[^\|]+)\|({alert_name}[^\|]+)\|({alert_severity}[^\|]+)\|""",
    """\WexternalId=({alert_id}\d+)""",
    """\Wstart=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\Wsuser=(?:(({user_lastname}[\w\']+), ({user_firstname}\w+))|({user}[^\s]+))\s+(\w+=|$)""",
    """\Wapp=({service}.+?)\s+(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s+(\w+=|$)""",
    """\Wmsg=[^=]+? against (?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]+)) from (?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w.\-]+))""",
    """\Wmsg=[^=]+? to (?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|([^\/]+\/)?({dest_host}[\w.\-]+)) from (?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w.\-]+))""",
    """\Wshost=(?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w.\-]+))\s+(\w+=|$)""",
  ]
}
```