#### Parser Content
```Java
{
Name = f5-asm-alert
  Vendor = F5
  Product = F5 BIG-IP Application Security Manager (ASM)
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ ASM:""", """HTTP""", """Cookie:""" ]
  Fields = [
    """\w+\s+\d+\s+\d\d:\d\d:\d\d\s+({host}[^\s]+)\s+(\w+\s+\d+\s+\d\d:\d\d:\d\d\s+({dest_host}[^\s]+)\s+)?ASM:""",
    """\sASM:("[^"]*",)"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sASM:("[^"]*",){2}"({dest_ip}[\da-fA-F\.:]+)""",
    """\sASM:("[^"]*",){3}"({src_ip}[\da-fA-F\.:]+)""",
    """\sASM:("[^"]*",){5}"({protocol}[^"]+)"""",
    """\sASM:("[^"]*",){8}"({additional_info}[^"]+)"""",
    """\sASM:("[^"]*",){8}"({alert_name}[^"]+)"""",
    """\sASM:"({alert_name}[^"]+)"""",
    """\sASM:("[^"]*",){9}"(?:N\/A|({user}[^"]+))"""",
    """\sASM:("[^"]*",){13}"\w+\s+({malware_url}[^"]+?)(?:\s+\w+\/\d\.\d|)((\\r\\n|\s+)[\w\-]+:|")""",
    """(\\r\\n|\s)Host:\s*({domain}[^"]+?)((\\r\\n|\s+)[\w\-]+:|")""",
    """(\\r\\n|\s)User-Agent:\s*({user_agent}[^"]+?)(\\r\\n[\w\-]+:|")""",
    """(\\r\\n|\s)User-Agent:\s*Mozilla\/.+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)"""
  ]
  DupFields = ["protocol->alert_type"]
}
```