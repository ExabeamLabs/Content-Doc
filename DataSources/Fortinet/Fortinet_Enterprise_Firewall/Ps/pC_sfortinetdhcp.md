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
    """\w+ \d{1,100} \d\d:\d\d:\d\d ({host}[\w\-.]{1,2000})""",
    """\Wip=({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """\Whostname="({dest_host}[\w\-.]{1,2000})""",
    """\Whostname="({user}[^"\s]{1,2000})"""
  ]
}
```