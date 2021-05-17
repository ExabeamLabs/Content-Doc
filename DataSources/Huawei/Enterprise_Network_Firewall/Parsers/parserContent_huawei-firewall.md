#### Parser Content
```Java
{
Name = huawei-firewall
  Vendor = Huawei
  Product = Enterprise Network Firewall
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = ["""rule-name=""" , """vsys=""" , """destination-ip""" , """POLICY/""" , """/POLICY"""]
  Fields = [
    """time=({time}\d\d\d\d\/\d{1,100}\/\d{1,100}\s{0,100}\d\d:\d\d:\d\d)"""
    """\s({host}[^\s]{1,2000})\s%""",
    """%*\d{0,100}POLICY\/\d\/POLICY({outcome}\w+)""",
    """protocol=({protocol}[^,]{1,2000})""",
    """source-ip=({src_ip}[^,]{1,2000})""",
    """source-port=({src_port}[^,]{1,2000})""",
    """destination-ip=({dest_ip}[^,]{1,2000})""",
    """destination-port=({dest_port}[^,]{1,2000})""",
    """rule-name=({rule}[^.]{1,2000})"""
  ]
}
```