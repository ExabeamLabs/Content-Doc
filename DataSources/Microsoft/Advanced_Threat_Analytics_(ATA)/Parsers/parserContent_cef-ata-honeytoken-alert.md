#### Parser Content
```Java
{
Name = cef-ata-honeytoken-alert
  Vendor = Microsoft
  Product = Advanced Threat Analytics (ATA)
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """|Microsoft|ATA|""", """|HoneytokenActivitySuspiciousActivity|""" ]
  Fields = [
    """exabeam_host=([^=@]+@)?({host}[\w.\-]+)""",
    """CEF:([^\|]*\|){4}({alert_type}[^\|]+)\|({alert_name}[^\|]+)\|({alert_severity}[^\|]+)\|""",
    """\Wstart=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\Wsuser=(?:(({user_lastname}[\w\']+), ({user_firstname}\w+))|({user}[^\s]+))\s{1,100}(\w+=|$)"""
    """\Wapp=({service}.+?)\s{1,100}(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """\Wmsg=[^=]+?performed by .+?(login to| from) (?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w.\-]+))""",
  ]
}
```