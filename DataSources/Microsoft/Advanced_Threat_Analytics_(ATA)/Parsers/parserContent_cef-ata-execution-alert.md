#### Parser Content
```Java
{
Name = cef-ata-execution-alert
  Vendor = Microsoft
  Product = Advanced Threat Analytics (ATA)
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """|Microsoft|ATA|""", """|RemoteExecutionSuspiciousActivity|""" ]
  Fields = [
    """exabeam_host=([^=@]+@)?({host}[\w.\-]+)""",
    """CEF:([^\|]*\|){4}({alert_type}[^\|]+)\|({alert_name}[^\|]+)\|({alert_severity}[^\|]+)\|""",
    """\WexternalId=({alert_id}\d{1,100})""",
    """\Wstart=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\Wmsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """\Wmsg=[^=]*?performed on ({host}\S+) from (?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w.\-]+))""",
    """\Wmsg=[^=]+?by (?:(({user_lastname}[\w\']+), ({user_firstname}\w+))|({user}\w+))""",
    """\Wsuser=(?:(({user_lastname}[\w\']+), ({user_firstname}\w+))|({user}[^\s]+))\s{1,100}(\w+=|$)""",
    """\Wshost=(?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w.\-]+))\s{1,100}(\w+=|$)""",
  ]
}
```