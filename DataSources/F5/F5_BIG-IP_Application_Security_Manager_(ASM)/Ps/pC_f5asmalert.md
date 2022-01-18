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
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s{1,100}(\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({dest_host}[^\s]{1,2000})\s{1,100})?ASM:""",
    """\sASM:("[^"]{0,2000}",)"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sASM:("[^"]{0,2000}",){2}"({dest_ip}[\da-fA-F\.:]{1,2000})""",
    """\sASM:("[^"]{0,2000}",){3}"({src_ip}[\da-fA-F\.:]{1,2000})""",
    """\sASM:("[^"]{0,2000}",){5}"({protocol}[^"]{1,2000})"""",
    """\sASM:("[^"]{0,2000}",){8}"({additional_info}[^"]{1,2000})"""",
    """\sASM:("[^"]{0,2000}",){8}"({alert_name}[^"]{1,2000})"""",
    """\sASM:"({alert_name}[^"]{1,2000})"""",
    """\sASM:("[^"]{0,2000}",){9}"(?:N\/A|({user}[^"]{1,2000}))"""",
    """\sASM:("[^"]{0,2000}",){13}"\w+\s{1,100}({malware_url}[^"]{1,2000}?)(?:\s{1,100}\w+\/\d\.\d|)((\\r\\n|\s{1,100})[\w\-]{1,2000}:|")""",
    """(\\r\\n|\s)Host:\s{0,100}({domain}[^"]{1,2000}?)((\\r\\n|\s{1,100})[\w\-]{1,2000}:|")""",
    """(\\r\\n|\s)User-Agent:\s{0,100}({user_agent}[^"]{1,2000}?)(\\r\\n[\w\-]{1,2000}:|")""",
    """(\\r\\n|\s)User-Agent:\s{0,100}Mozilla\/.+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)"""
  ]
  DupFields = ["protocol->alert_type"]


}
```