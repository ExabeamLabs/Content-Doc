#### Parser Content
```Java
{
Name = f5-asm-alert-1
  Vendor = F5
  Product = F5 Application Security Manager
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ ASM:""", """,web_application_name="""", """,response_code="""" ]
  Fields = [
    """date_time="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+ \d\d \d\d:\d\d:\d\d ({dest_host}[\w\-.]+) ASM:""",
    """unit_hostname="({host}[^"]+)""",
    """ip_client="({src_ip}[A-Fa-f:\d.]+)""",
    """UserID=({user}[^\s,]+)""",
    """username="(N\/A|({user}[^"]+))"""",
    """src_port="({src_port}\d+)""",
    """dest_port="({dest_port}\d+)""",
    """dest_ip="({dest_ip}[A-Fa-f:\d.]+)""",
    """uri="({malware_url}[^"]+)""",
    """,policy_name="(|({alert_name}[^"]+))"""",
    """,violations="(|({alert_name}[^"]+))"""",
    """,violation_rating="(|({alert_severity}[^"]+))"""",
    """protocol="({protocol}[^"]+)""",
    """protocol="({alert_type}[^"]+)""",
    """,attack_type="(|({alert_type}[^"]+))"""",
    """,virus_name="(N\/A|({malware_file_name}[^"]+))"""",
    """(\\r\\n|\s)Host:\s*({domain}[^"]+?)((\\r\\n|\s+)[\w\-]+:|")""",
    """(\\r\\n|\s)User-Agent:\s*({user_agent}[^"]+?)(\\r\\n[\w\-]+:|")""",
    """(\\r\\n|\s)User-Agent:\s*Mozilla\/.+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)"""
  ]
  DupFields = [ "browser->process" ]
}
```