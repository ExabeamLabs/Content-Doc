#### Parser Content
```Java
{
Name = f5-asm-alert-1
  Vendor = F5
  Product = F5 BIG-IP Application Security Manager (ASM)
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ ASM:""", """,web_application_name="""", """,response_code="""" ]
  Fields = [
    """date_time="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({dest_host}[^\s]{1,2000}) ASM:""",
    """unit_hostname="({host}[^"]{1,2000})""",
    """ip_client="({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """UserID=({user}[^\s,]{1,2000})""",
    """username="(N\/A|({user}[^"]{1,2000}))"""",
    """src_port="({src_port}\d{1,100})""",
    """dest_port="({dest_port}\d{1,100})""",
    """dest_ip="({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """uri="(\/|({malware_url}[^"]{1,2000}?))\s{0,100}"""",
    """policy_name="({policy_name}[^"]{1,2000})"""",
    """policy_name="({alert_name}[^"]{1,2000})"""",
    """,violations="({alert_name}[^"]{1,2000})"""",
    """violation_rating="({alert_severity}[^"]{1,2000})"""",
    """protocol="({protocol}[^"]{1,2000})""",
    """protocol="({alert_type}[^"]{1,2000})""",
    """,attack_type="({alert_type}[^"]{1,2000})"""",
    """virus_name="(N\/A|({malware_file_name}[^"]{1,2000}))"""",
    """Host:\s{0,100}({domain}[^"]{1,2000}?)((\\r\\n|\s{1,100})[\w\-]{1,2000}:|")""",
    """User-Agent:\s{0,100}({user_agent}[^"]{1,2000}?)\s{0,100}(\\r\\n[\w\-]{1,2000}:|")""",
    """User-Agent:\s{0,100}Mozilla\/.+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """geo_location="(N\/A|({country}[^"]{1,2000}))"""",
    """ip_address_intelligence="(N\/A|({ip_reputation}[^"]{1,2000}))""""
  ]
}
```