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
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}[^\s]+)""",
    """\sdvchost=({host}[^\s]+)""",
    """\sdst=({dest_ip}[^\s]+)""",
    """\sdhost=({dest_host}[^\s]+)""",
    """\sduser=({user_fullname}(\w+\s{1,100})+\w+)\s{1,100}(\w+=|$)""",
    """\sduser=({user}[^\s@]+)\s{1,100}(\w+=|$)""",
    """\sduser=({user_email}[^\s@]+@[^\s@]+)\s{1,100}(\w+=|$)""",
  ]
}
```