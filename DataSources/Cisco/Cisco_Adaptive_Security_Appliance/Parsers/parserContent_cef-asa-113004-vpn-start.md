#### Parser Content
```Java
{
Name = cef-asa-113004-vpn-start
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = NitroCefSyslog
  DataType = "nac-logon"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""" , """|CISCO|ASA|""", """|113004|""" ,"""AAA user authentication Successful"""]
  Fields = [
    """\srt=({time}\d+)""",
    """\sdvc=({host}[^\s]+)""",
    """\sdvchost=({host}[^\s]+)""",
    """\sdst=({dest_ip}[^\s]+)""",
    """\sdhost=({dest_host}[^\s]+)""",
    """\sduser=({user_fullname}(\w+\s+)+\w+)\s+(\w+=|$)""",
    """\sduser=({user}[^\s@]+)\s+(\w+=|$)""",
    """\sduser=({user_email}[^\s@]+@[^\s@]+)\s+(\w+=|$)""",
  ]
}
```