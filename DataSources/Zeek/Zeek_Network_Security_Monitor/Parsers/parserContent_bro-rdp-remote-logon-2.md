#### Parser Content
```Java
{
Name = bro-rdp-remote-logon-2
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "epoch"
  Conditions = [ "\t3389\t", "\tSuccess\tRDP\t" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d+)""",
    """([^\t]+\t){2}(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\t]+))\t({src_port}\d+)""",
    """([^\t]+\t){4}(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\t]+))\t({dest_port}\d+)""",
    """([^\t]+\t){11}({src_host}[^\t]+)""",
    """3389\t(?:\(empty\)|(({domain}[^\\]+)\\+)?({user}.*?))\tSuccess"""
  ]
}
```