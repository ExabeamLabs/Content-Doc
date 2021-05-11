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
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """(Juniper:|PulseSecure:)\s{1,100}\S+\s{1,100}\S+\s{1,100}-\s{1,100}({host}[\w\.\-]+)\s{1,100}-""",
    """(Juniper:|PulseSecure:)\s{1,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\s{1,100}-\s{1,100}\[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]""",
    """\s{1,100}-\s{1,100}\[[^\]]+\]\s{1,100}(({domain}[^\(]+)\\)?({user}.+?)\(""",
    """\sConnected to\s{1,100}(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\.-]+))\s{1,100}port""",
  ]
  DupFields = ["user->account"]
}
```