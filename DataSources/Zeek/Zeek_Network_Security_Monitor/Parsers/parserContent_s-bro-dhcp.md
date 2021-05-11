#### Parser Content
```Java
{
Name = s-bro-dhcp
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Splunk
  DataType = "dhcp"
  TimeFormat = "epoch_sec"
  Conditions = [ "\tudp\t", "\tAUTH\t", "\tah_auth:" ]
  Fields = [
    """({time}\d{10})\.\d{1,100}\t({host}\S+)\t""",
    """\tah_auth:[^\t]*?\(ip=({dest_ip}[^)]+)\)""",
    """\tah_auth:[^\t]*?\s{1,100}ip\s{1,100}({dest_ip}[^\s]+)""",
    """\tah_auth:[^\t]*?\(hostname=({dest_host}[^)]+)\)""",
    """\tah_auth:[^\t]*?\s{1,100}hostname\s{1,100}({dest_host}[^\s]+)""",
    """\tah_auth:[^\t]*?\(hostname=({user}[^)]+)\)""",
    """\tah_auth:[^\t]*?\s{1,100}hostname\s{1,100}({user}[^\s]+)""",
    """\tah_auth:[^\t]*?\s{1,100}username\s{1,100}(({domain}[^\\]+)\\+)?({user}[^\\\s]+)""",
  ]
}
```