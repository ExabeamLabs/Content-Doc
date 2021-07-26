#### Parser Content
```Java
{
Name = zscaler-firewall
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Direct
  DataType = "network-connection"
  TimeFormat="MMM dd HH:mm:ss yyyy"
  Conditions = ["""department""", """avgduration""", """locationname"""]
  Fields = [
     """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
     """({time}\w{3}\s{1,100}\d{1,100}\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
     """action=({outcome}[^\s]{1,2000})""",
     """user=(({user_email}[^@]{1,2000}@[^\s]{0,2000})|({user}[^\s]{1,2000}))\s""",
     """csip=({src_ip}[^\s]{1,2000})""",
     """sdip=({dest_ip}[^\s]{1,2000})""",
     """sdport=({dest_port}[^\s]{1,2000})""",
     """csport=({src_port}[^\s]{1,2000})""",
     """proto=({protocol}[^\s]{1,2000})""",
     """inbytes=({bytes_in}[^\s]{1,2000})""",
     """outbytes=({bytes_out}[^\s]{1,2000})""",
     """department=({department}[^\=]{1,2000}?)\s{1,100}\w+=""",
     """locationname=({location}[^\=]{1,2000}?)\s{1,100}\w+=""",
     """tsip=(0\.0\.0\.0|({tunnel_src_ip}[\da-fA-F.:]{1,2000}))""",
     """tunsport=({tunnel_src_port}\d{1,100})""",
     """tuntype=({tunnel_type}[^\s]{1,2000})""",
     """destcountry=((?i)Other|({dest_country}[^\=]{1,2000}?)\s{1,100}\w+=)""",
     """nwsvc=({dest_service}[^\s]{1,2000})""",
     """devicehostname=(NA|({host}[^"]{1,2000}?)\s{0,100}(\w+=|"{0,20}$))""",
     """ipcat=(Miscellaneous or Unknown|({ip_category}[^\=]{1,2000}?)\s{1,100}\w+=)""",
     """deviceowner=(NA|({device_owner}[^\s]{1,2000}))""",
     """rulelabel=({rule}.+?)\s{0,100}inbytes"""
  ]
  DupFields = ["outcome->action"]
}
```