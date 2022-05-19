#### Parser Content
```Java
{
Name = s-cisco-acs-nac-logon
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Splunk
  DataType = "windows-nac-logon"
  TimeFormat = "epoch_sec"
  Conditions = [ """Acct-Authentic = RADIUS""", """Acct-Status-Type = Start""", """Acct-Unique-Session-Id =""" ]
  Fields = [
           """Timestamp = ({time}\d{10})""",
           """exabeam_host=({host}[^\s]{1,2000})""",
           """User-Name = "(({domain}[^\\"]{1,2000})\\+)?(?!((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|((\w{2}:){5}\w{2})|(host\/)))({user}[^"]{1,2000})"""",
           """NAS-Identifier = "({location}[^"]{1,2000})"""",
           """Calling-Station-Id = "({src_mac}[^"]{1,2000})"""",
           """NAS-IP-Address = ({dest_ip}[\da-fA-F\.:]{1,2000})""",
           """Framed-IP-Address = ({dest_ip}[\da-fA-F\.:]{1,2000})""",
  ]


}
```