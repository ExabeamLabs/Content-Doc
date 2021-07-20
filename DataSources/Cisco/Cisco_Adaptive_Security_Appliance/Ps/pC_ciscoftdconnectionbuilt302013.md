#### Parser Content
```Java
{
Name = cisco-ftd-connection-built-302013
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "%FTD-", "-30201", ": Built ", " connection "]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]{1,2000})\s{0,100}:\s{0,100}%FTD-""",
    """%FTD-({priority}\d{1,100})-({event_code}\d{1,100})""",
    """({event_name}Built ({direction}inbound|outbound) ({protocol}TCP|UDP) connection)""",
    """\sconnection\s{1,100}({connection_id}\d{1,100})\s{1,100}for""",
"""Built outbound.*?for\s{1,100}({dest_interface}.+?):(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|({dest_host}[^\s]{1,2000}?))((\/({dest_port}\d{1,100})\s{1,100})|\s{1,100})\((({dest_translated_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|({dest_translated_host}[^\s]{1,2000}?))(\/({dest_translated_port}\d{1,100}))?\)(\(.+?\))?\s{1,100}to\s{1,100}({src_interface}.+?):(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|({src_host}[^\s]{1,2000}?))((\/({src_port}\d{1,100})\s{1,100})|\s{1,100})\((({src_translated_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|({src_translated_host}[^\s]{1,2000}?))(\/({src_translated_port}\d{1,100}))?\)(\s{1,100}\(({user}.+?)\))?""",
"""Built inbound.*?for\s{1,100}({src_interface}.+?):(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|({src_host}[^\s]{1,2000}?))((\/({src_port}\d{1,100})\s{1,100})|\s{1,100})\((({src_translated_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|({src_translated_host}[^\s]{1,2000}?))(\/({src_translated_port}\d{1,100}))?\)(\(.+?\))?\s{1,100}to\s{1,100}({dest_interface}.+?):(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|({dest_host}[^\s]{1,2000}?))((\/({dest_port}\d{1,100})\s{1,100})|\s{1,100})\((({dest_translated_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|({dest_translated_host}[^\s]{1,2000}?))(\/({dest_translated_port}\d{1,100}))?\)(\s{1,100}\(({user}.+?)\))?"""

 ]
}
```