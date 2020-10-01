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
    """({time}\d{10})\.\d+\t({host}\S+)\t""",
    """\tah_auth:[^\t]*?\(ip=({dest_ip}[^)]+)\)""",
    """\tah_auth:[^\t]*?\s+ip\s+({dest_ip}[^\s]+)""",
    """\tah_auth:[^\t]*?\(hostname=({dest_host}[^)]+)\)""",
    """\tah_auth:[^\t]*?\s+hostname\s+({dest_host}[^\s]+)""",
    """\tah_auth:[^\t]*?\(hostname=({user}[^)]+)\)""",
    """\tah_auth:[^\t]*?\s+hostname\s+({user}[^\s]+)""",
    """\tah_auth:[^\t]*?\s+username\s+(({domain}[^\\]+)\\+)?({user}[^\\\s]+)""",
  ]
}
```