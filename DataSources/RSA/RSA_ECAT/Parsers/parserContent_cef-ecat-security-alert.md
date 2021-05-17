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
    """CEF([^\|]{0,2000}\|){4}({alert_type}[^\|]{1,2000})""",
    """\sshost=({dest_host}.+?)\s{1,100}(\w+=|$)""",
    """\ssrc=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\sfname=({process_name}.+?)\s{1,100}(\w+=|$)""",
    """\sinstantIOCName=({alert_name}.+?)\s{1,100}(\w+=|$)""",
    """\smachineScore=({alert_severity}\d{1,100})""",
    """\smoduleSignature=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """\sos=({threat_category}.+?)\s{1,100}(\w+=|$)""",
    """\stargetModule=({malware_url}.+?)\s{1,100}(\w+=|$)""",
  ]
  DupFields = [ "dest_host->host" , "malware_url->process_name"]
}
```