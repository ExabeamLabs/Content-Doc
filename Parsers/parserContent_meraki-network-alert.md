#### Parser Content
```Java
{
Name = meraki-network-alert
  Vendor = Cisco
  Product = Cisco Meraki MX appliances
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """ security_event """, """ ids_alerted """, """ timestamp=""" ]
  Fields = [
    """({host}[\w.\-]+)\s+(\S+\s+){2}security_event""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d+)""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({dest_port}\d+)""",
    """\sprotocol=({protocol}\w+)""",
    """\ssignature=({alert_type}\S+)""",
    """\spriority=({alert_severity}\d+)""",
    """\stimestamp=({time}\d+)""",
    """\sdirection=({direction}\S+)""",
    """\smessage:\s*({alert_name}.+?)\s*$""",
    """\sdhost=({dest_host}\S+)""",
  ]
  DupFields = [ "alert_name->alert_type"]
}
```