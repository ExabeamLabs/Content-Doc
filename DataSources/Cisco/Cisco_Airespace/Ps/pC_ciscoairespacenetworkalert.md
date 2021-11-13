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
    """dvchost=({host}[^=]{1,2000}?)\s{1,100}\w+=""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({alert_type}Airespace)""",
    """\|Cisco\|([^\|]{0,2000}\|){3}({alert_name}[^\|]{1,2000})\|(Unknown|({alert_severity}[^\|]{1,2000}))""",
    """\|Cisco\|([^\|]{0,2000}\|){2}({alert_type}[^\|\d]{1,2000})\s{0,100}\|""",
    """eventId=({alert_id}\d{1,100})""",
    """src=(0.0.0.0|({src_ip}[a-fA-F:\d.]{1,2000}))""",
    """categoryOutcome=(\/)?({outcome}[^=]{1,2000}?)\s{1,100}\w+=""",
    """categorySignificance=(\/)?({category_significance}[^=\/]{1,2000}?)\s{1,100}\w+=""",
    """categoryBehavior=(\/)?({category_behavior}[^=]{1,2000}?)\s{1,100}\w+=""",
    """smac=({src_mac}[^=]{1,2000}?)\s{1,100}\w+=""",
    """dmac=({dest_mac}[^=]{1,2000}?)\s{1,100}\w+=""",
    """dvc=({host_ip}[a-fA-F:\d.]{1,2000})"""
  ] 


}
```