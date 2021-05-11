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
    """dvchost=({host}[^=]+?)\s{1,100}\w+=""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({alert_type}Airespace)""",
    """\|Cisco\|([^\|]*\|){3}({alert_name}[^\|]+)\|(Unknown|({alert_severity}[^\|]+))""",
    """\|Cisco\|([^\|]*\|){2}({alert_type}[^\|\d]+)\s{0,100}\|""",
    """eventId=({alert_id}\d{1,100})""",
    """src=(0.0.0.0|({src_ip}[a-fA-F:\d.]+))""",
    """categoryOutcome=(\/)?({outcome}[^=]+?)\s{1,100}\w+=""",
    """categorySignificance=(\/)?({category_significance}[^=\/]+?)\s{1,100}\w+=""",
    """categoryBehavior=(\/)?({category_behavior}[^=]+?)\s{1,100}\w+=""",
    """smac=({src_mac}[^=]+?)\s{1,100}\w+=""",
    """dmac=({dest_mac}[^=]+?)\s{1,100}\w+=""",
    """dvc=({host_ip}[a-fA-F:\d.]+)"""
  ] 
}
```