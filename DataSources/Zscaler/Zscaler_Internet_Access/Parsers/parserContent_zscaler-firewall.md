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
     """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
     """({time}\w{3}\s{1,100}\d{1,100}\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
     """action=({outcome}[^\s]+)""",
     """user=(({user_email}[^@]+@[^\s]*)|({user}[^\s]+))\s""",
     """csip=({src_ip}[^\s]+)""",
     """sdip=({dest_ip}[^\s]+)""",
     """sdport=({dest_port}[^\s]+)""",
     """csport=({src_port}[^\s]+)""",
     """proto=({protocol}[^\s]+)""",
     """inbytes=({bytes_in}[^\s]+)""",
     """outbytes=({bytes_out}[^\s]+)""",
     """department=({department}[^\=]+?)\s{1,100}\w+=""",
     """locationname=({location}[^\=]+?)\s{1,100}\w+=""",
     """tsip=(0\.0\.0\.0|({tunnel_src_ip}[\da-fA-F.:]+))""",
     """tunsport=({tunnel_src_port}\d{1,100})""",
     """tuntype=({tunnel_type}[^\s]+)""",
     """destcountry=((?i)Other|({dest_country}[^\=]+?)\s{1,100}\w+=)""",
     """nwsvc=({dest_service}[^\s]+)""",
     """devicehostname=(NA|({host}[^"]+?)\s{0,100}(\w+=|"{0,20}$))""",
     """ipcat=(Miscellaneous or Unknown|({ip_category}[^\=]+?)\s{1,100}\w+=)""",
     """deviceowner=(NA|({device_owner}[^\s]+))""",
     """rulelabel=({rule}.+?)\s{0,100}inbytes"""
  ]
  DupFields = ["outcome->action"]
}
```