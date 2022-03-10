#### Parser Content
```Java
{
Name = cisco-asa-network-connection-successful
  Vendor = Cisco
  Product = Adaptive Security Appliance
  Lms = Splunk
  DataType = "network-connection-successful"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """%ASA-""", """-302015""", """: Built outbound """, """ connection """]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\w{1,3}\s\d{1,2}\s\d\d\d\d\s\d\d:\d\d:\d\d)""",
    """\s\d\d:\d\d:\d\d\s({host}[^\s]{1,2000})""",
    """%ASA-({priority}\d{1,100})-({event_code}\d{1,100})""",
    """({event_name}Built ({direction}outbound) ({protocol}TCP|UDP) connection)""",
    """\sconnection\s{1,100}({connection_id}\d{1,100})\s{1,100}for""",
    """Built outbound[^\n]{1,2000}?for\s{1,100}({dest_interface}[^:]{1,2000}):((::ffff:)?({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9]{0,2000}:[A-Fa-f0-9:]{1,2000}(th0)?))|(::ffff:)?({dest_host}[^\s]{1,2000}?))((\/({dest_port}\d{1,100})\s{1,100})|\s{1,100})\(((::ffff:)?({dest_translated_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9]{0,2000}:[A-Fa-f0-9:]{1,2000}(th0)?))|(::ffff:)?({dest_translated_host}[^\s]{1,2000}?))(\/({dest_translated_port}\d{1,100}))?\)\s{1,100}to\s{1,100}({src_interface}[^:]{1,2000}):((::ffff:)?({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9]{0,2000}:[A-Fa-f0-9:]{1,2000}(th0)?))|(::ffff:)?({src_host}[^\s]{1,2000}?))((\/({src_port}\d{1,100})\s{1,100})|\s{1,100})\(((::ffff:)?({src_translated_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9]{0,2000}:[A-Fa-f0-9:]{1,2000}(th0)?))|(::ffff:)?({src_translated_host}[^\s]{1,2000}?))(\/({src_translated_port}\d{1,100}))?\)(\s{1,100}\(({user}[^\)]{1,2000})\))?"""
  ]


}
```