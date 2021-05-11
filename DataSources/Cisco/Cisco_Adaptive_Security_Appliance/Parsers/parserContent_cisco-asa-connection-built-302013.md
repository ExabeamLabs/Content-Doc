#### Parser Content
```Java
{
Name = cisco-asa-connection-built-302013
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "%ASA-", "-302013", ": Built ", " connection "]
  Fields = [
    """({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d{1,100})""",
    """exabeam_host=(::ffff:)?({host}[^\s]+)""",
    """(\w{3} (\d\d| \d) (\d\d\d\d )?(\d\d| \d):\d\d:\d\d)\s{1,100}(GMT|(::ffff:)?({host}[\w.\-:]+?[^:]))\s{0,100}:?\s{0,100}%ASA-""",
    """<\d{1,100}>(::ffff:)?({host}[\w.\-:]+?[^:])\s{1,100}%ASA-""",
    """%ASA-({priority}\d{1,100})-({event_code}\d{1,100})""",
    """({event_name}Built ({direction}inbound|outbound) ({protocol}TCP|UDP) connection)""",
    """\sconnection\s{1,100}({connection_id}\d{1,100})\s{1,100}for""",
    """Built outbound.*?for\s{1,100}({dest_interface}.+?):((::ffff:)?({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|(::ffff:)?({dest_host}[^\s]+?))((\/({dest_port}\d{1,100})\s{1,100})|\s{1,100})\(((::ffff:)?({dest_translated_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|(::ffff:)?({dest_translated_host}[^\s]+?))(\/({dest_translated_port}\d{1,100}))?\)(\(.+?\))?\s{1,100}to\s{1,100}({src_interface}.+?):((::ffff:)?({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|(::ffff:)?({src_host}[^\s]+?))((\/({src_port}\d{1,100})\s{1,100})|\s{1,100})\(((::ffff:)?({src_translated_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|(::ffff:)?({src_translated_host}[^\s]+?))(\/({src_translated_port}\d{1,100}))?\)(\s{1,100}\(({user}.+?)\))?""",
    """Built inbound.*?for\s{1,100}({src_interface}.+?):((::ffff:)?({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|(::ffff:)?({src_host}[^\s]+?))((\/({src_port}\d{1,100})\s{1,100})|\s{1,100})\(((::ffff:)?({src_translated_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|(::ffff:)?({src_translated_host}[^\s]+?))(\/({src_translated_port}\d{1,100}))?\)(\(.+?\))?\s{1,100}to\s{1,100}({dest_interface}.+?):((::ffff:)?({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|(::ffff:)?({dest_host}[^\s]+?))((\/({dest_port}\d{1,100})\s{1,100})|\s{1,100})\(((::ffff:)?({dest_translated_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|(::ffff:)?({dest_translated_host}[^\s]+?))(\/({dest_translated_port}\d{1,100}))?\)(\s{1,100}\(({user}.+?)\))?"""
 ]
}
```