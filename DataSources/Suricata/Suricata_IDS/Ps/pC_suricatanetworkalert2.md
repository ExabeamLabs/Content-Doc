#### Parser Content
```Java
{
Name = suricata-network-alert-2
  Vendor = Suricata
  Product = Suricata IDS
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """flow_id""", """event_type""", """community_id""", """action""", """signature""", """category"""]
  Fields = [
    """"timestamp\\?":\\?"({time}\d{1,100}-\d{1,100}-\d{1,1000}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}\+\d{1,100})""",
    """"src_ip\\?":\\?"({src_ip}[A-Fa-f:.\d]{1,2000})""",
    """"src_port\\?":\\?({src_port}\d{1,100})""",
    """"dest_ip\\?":\\?"({dest_ip}[A-Fa-f:.\d]{1,2000})""",
    """"dest_port\\?":\\?({dest_port}\d{1,100})""",
    """"proto\\?":\\?"({protocol}[^""\\]{1,2000})""",
    """"flow_id\\?":\\?({alert_id}\d{1,100})"""
    """"severity\\?":\\?({alert_severity}\d{1,100})"""
    """"{1,20}signature\\"{1,20}:\s{0,100}\\"{1,20}({rule_name}[^\\"]{1,2000})\\"""",
    """"{1,20}signature_id\\"{1,20}:\s{0,100}\\({rule_id}\d{1,100})""",
    """"{1,20}action\\"{1,20}:\s{0,100}"{1,20}\\({action}[^\\"]{1,2000})""",
    """"host":\{"name":"({host}[^"]{1,2000})""",
    """"{1,20}category\\"{1,20}:\s{0,100}\\"{1,20}({alert_type}[^\\"]{1,2000})\\"{1,20}""",
    """"payload_printable\\":\\"({payload_printable}[^,]{1,2000})\\",""",
    """msg:\\{1,100}"{0,1000}({alert_name}[^"\\]{1,2000})""",
    """"{1,20}category"{1,20}:\s{0,100}"{1,20}({category}[^"]{1,2000})""",
    """"app_proto\\":\\"({app_proto}[^\\"]{1,2000})""",
    """"rule\\":\\"({rule}[^,\("\\]{1,2000}?)\s{0,100}(\(|"|\\)"""
    
  ]
}
}
```