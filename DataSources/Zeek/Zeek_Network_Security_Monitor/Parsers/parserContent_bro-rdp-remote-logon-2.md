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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({time}\d{1,100})""",
    """([^\t]{1,2000}\t){2}(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\t]{1,2000}))\t({src_port}\d{1,100})""",
    """([^\t]{1,2000}\t){4}(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\t]{1,2000}))\t({dest_port}\d{1,100})""",
    """([^\t]{1,2000}\t){11}({src_host}[^\t]{1,2000})""",
    """3389\t(?:\(empty\)|(({domain}[^\\]{1,2000})\\+)?({user}.*?))\tSuccess"""
  ]
}
```