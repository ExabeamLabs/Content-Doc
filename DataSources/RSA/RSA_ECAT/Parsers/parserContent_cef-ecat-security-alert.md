#### Parser Content
```Java
{
Name = cef-ecat-security-alert
  Vendor = RSA
  Product = RSA ECAT
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "M/d/yyyy HH:mm:ss a"
  Conditions = [ """|RSA|RSA ECAT|""", """|EcatAlert|""" ]
  Fields = [
    """CEF([^\|]*\|){4}({alert_type}[^\|]+)""",
    """\sshost=({dest_host}.+?)\s+(\w+=|$)""",
    """\ssrc=({dest_ip}[a-fA-F\d.:]+)""",
    """\sfname=({process_name}.+?)\s+(\w+=|$)""",
    """\sinstantIOCName=({alert_name}.+?)\s+(\w+=|$)""",
    """\smachineScore=({alert_severity}\d+)""",
    """\smoduleSignature=({additional_info}.+?)\s+(\w+=|$)""",
    """\sos=({threat_category}.+?)\s+(\w+=|$)""",
    """\stargetModule=({malware_url}.+?)\s+(\w+=|$)""",
  ]
  DupFields = [ "dest_host->host" , "malware_url->process_name"]
}
```