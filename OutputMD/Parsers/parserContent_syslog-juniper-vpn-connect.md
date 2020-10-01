#### Parser Content
```Java
{
Name = syslog-juniper-vpn-connect
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Juniper: """, """ - Connected to""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """(Juniper:|PulseSecure:)\s+\S+\s+\S+\s+-\s+({host}[\w\.\-]+)\s+-""",
    """(Juniper:|PulseSecure:)\s+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\s+-\s+\[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]""",
    """\s+-\s+\[[^\]]+\]\s+(({domain}[^\(]+)\\)?({user}.+?)\(""",
    """\sConnected to\s+(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\.-]+))\s+port""",
  ]
  DupFields = ["user->account"]
}
```