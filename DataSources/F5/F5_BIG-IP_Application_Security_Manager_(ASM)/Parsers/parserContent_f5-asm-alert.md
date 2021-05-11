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
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[^\s]+)\s{1,100}(\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({dest_host}[^\s]+)\s{1,100})?ASM:""",
    """\sASM:("[^"]*",)"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sASM:("[^"]*",){2}"({dest_ip}[\da-fA-F\.:]+)""",
    """\sASM:("[^"]*",){3}"({src_ip}[\da-fA-F\.:]+)""",
    """\sASM:("[^"]*",){5}"({protocol}[^"]+)"""",
    """\sASM:("[^"]*",){8}"({additional_info}[^"]+)"""",
    """\sASM:("[^"]*",){8}"({alert_name}[^"]+)"""",
    """\sASM:"({alert_name}[^"]+)"""",
    """\sASM:("[^"]*",){9}"(?:N\/A|({user}[^"]+))"""",
    """\sASM:("[^"]*",){13}"\w+\s{1,100}({malware_url}[^"]+?)(?:\s{1,100}\w+\/\d\.\d|)((\\r\\n|\s{1,100})[\w\-]+:|")""",
    """(\\r\\n|\s)Host:\s{0,100}({domain}[^"]+?)((\\r\\n|\s{1,100})[\w\-]+:|")""",
    """(\\r\\n|\s)User-Agent:\s{0,100}({user_agent}[^"]+?)(\\r\\n[\w\-]+:|")""",
    """(\\r\\n|\s)User-Agent:\s{0,100}Mozilla\/.+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)"""
  ]
  DupFields = ["protocol->alert_type"]
}
```