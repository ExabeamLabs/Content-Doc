#### Parser Content
```Java
{
Name = exa-syslog-nac-logon-1
  Conditions = [ """ joins WLAN[""", """ AP[""", """User[""" ]

exa-syslog-nac-logon = {
  Vendor = Ruckus
  Product = Ruckus
  Lms = Direct
  DataType = "nac-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """User\s{0,100}\[({user}[\w.\-]{1,2000})(@({domain}[\w.\-]{1,2000}))?(@({src_mac}(\w{2}:){5}\w{2}))?\]""",
    """User\s{0,100}\[({src_mac}(\w{2}:){5}\w{2})\]""",
    """User\s{0,100}\[host\/({src_host}[\w\-]{1,2000})(@({src_mac}(\w{2}:){5}\w{2}))?\]""",
    """WLAN\[({ssid}[^\]]{1,2000})""",
    """AP\[({wifiap}[^@\]]{1,2000})""",
  ]
  DupFields = [ "host->auth_server", "ssid->network", "wifiap->dest_host" 
}
```