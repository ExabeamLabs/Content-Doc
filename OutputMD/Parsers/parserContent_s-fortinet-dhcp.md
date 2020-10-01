#### Parser Content
```Java
{
Name = s-fortinet-dhcp
  Vendor = Fortinet
  Product = Fortinet Enterprise Firewall
  Lms = Splunk
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd' time='HH:mm:ss"
  Conditions = [ """ logver=""", """ logdesc="""", """ dhcp_msg="""" ]
  Fields = [
    """\Wdate=({time}\d\d\d\d\-\d\d\-\d\d time\=\d\d:\d\d:\d\d)""",
    """\w+ \d+ \d\d:\d\d:\d\d ({host}[\w\-.]+)""",
    """\Wip=({dest_ip}[a-fA-F:\d.]+)""",
    """\Whostname="({dest_host}[\w\-.]+)""",
    """\Whostname="({user}[^"\s]+)"""
  ]
}
```