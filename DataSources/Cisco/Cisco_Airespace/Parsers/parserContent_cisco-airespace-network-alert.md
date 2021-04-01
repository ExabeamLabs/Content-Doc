#### Parser Content
```Java
{
Name = cisco-airespace-network-alert
  Vendor = Cisco
  Product = Cisco Airespace
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF:""" , """|Cisco|Airespace|""", """dvchost=""", """catdt=Network-based IDS"""  ]
  Fields = [
    """dvchost=({host}[^=]+?)\s+\w+=""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({alert_type}Airespace)""",
    """\|Cisco\|([^\|]*\|){3}({alert_name}[^\|]+)\|(Unknown|({alert_severity}[^\|]+))""",
    """\|Cisco\|([^\|]*\|){2}({alert_type}[^\|\d]+)\s*\|""",
    """eventId=({alert_id}\d+)""",
    """src=(0.0.0.0|({src_ip}[a-fA-F:\d.]+))""",
    """categoryOutcome=(\/)?({outcome}[^=]+?)\s+\w+=""",
    """categorySignificance=(\/)?({category_significance}[^=\/]+?)\s+\w+=""",
    """categoryBehavior=(\/)?({category_behavior}[^=]+?)\s+\w+=""",
    """smac=({src_mac}[^=]+?)\s+\w+=""",
    """dmac=({dest_mac}[^=]+?)\s+\w+=""",
    """dvc=({host_ip}[a-fA-F:\d.]+)"""
  ] 
}
```