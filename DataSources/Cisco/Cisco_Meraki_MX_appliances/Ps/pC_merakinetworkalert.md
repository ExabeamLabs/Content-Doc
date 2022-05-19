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
    """({host}[\w.\-]{1,2000})\s{1,100}(\S+\s{1,100}){2}security_event""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d{1,100})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({dest_port}\d{1,100})""",
    """\sprotocol=({protocol}\w+)""",
    """\ssignature=({alert_type}\S+)""",
    """\spriority=({alert_severity}\d{1,100})""",
    """\stimestamp=({time}\d{1,100})""",
    """\sdirection=({direction}\S+)""",
    """\smessage:\s{0,100}({alert_name}.+?)\s{0,100}$""",
    """\sdhost=({dest_host}\S+)""",
  ]
  DupFields = [ "alert_name->alert_type"]


}
```