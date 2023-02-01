#### Parser Content
```Java
{
Name = f5-asm-alert-3
  Vendor = F5
  Product = F5 BIG-IP Application Security Manager (ASM)
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """device_vendor="F5"""", """device_product="ASM"""", """"Traffic Share Increased"""", """dos_attack_id="""" ]
  Fields = [
    """({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}(\+|-)\d{2}:\d{2})\s({host}[\w.-]{1,2000})""",
    """dos_attack_event="({event_name}[^"]{1,2000})"""",
    """dos_attack_name="({alert_name}[^"]{1,2000})"""",
    """source_ip="((N\/A)|({src_ip}[^"]{1,2000}))"""",
    """client_ip_geo_location="(N\/A|({country}[^"]{1,2000}))""""
  ]


}
```