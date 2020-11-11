#### Parser Content
```Java
{
Name = zscaler-firewall
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = ["""department""" , """avgduration""", """locationname"""]
  Fields = [
     """exabeam_host=([^=]+@\s*)?({host}\S+)""",
     """({time}\w{3}\s\d+\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
     """action=({outcome}[^\s]+)""",
     """user=(({user_email}[^@]+@[^\s]*)|({user}[^\s]+))\s""",
     """csip=({src_ip}[^\s]+)""",
     """cdip=({dest_ip}[^\s]+)""",
     """cdport=({dest_port}[^\s]+)""",
     """csport=(src_port}[^\s]+)""",
     """proto=({protocol}[^\s]+)""",
     """inbytes=({bytes_in}[^\s]+)""",
     """outbytes=({bytes_out}[^\s]+)""",
     """rulelabel=({rule}.+?)\s*inbytes"""
  ]
}
```