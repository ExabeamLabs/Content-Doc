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
    """\tah_auth:[^\t]{0,2000}?\(ip=({dest_ip}[^)]{1,2000})\)""",
    """\tah_auth:[^\t]{0,2000}?\s{1,100}ip\s{1,100}({dest_ip}[^\s]{1,2000})""",
    """\tah_auth:[^\t]{0,2000}?\(hostname=({dest_host}[^)]{1,2000})\)""",
    """\tah_auth:[^\t]{0,2000}?\s{1,100}hostname\s{1,100}({dest_host}[^\s]{1,2000})""",
    """\tah_auth:[^\t]{0,2000}?\(hostname=({user}[^)]{1,2000})\)""",
    """\tah_auth:[^\t]{0,2000}?\s{1,100}hostname\s{1,100}({user}[^\s]{1,2000})""",
    """\tah_auth:[^\t]{0,2000}?\s{1,100}username\s{1,100}(({domain}[^\\]{1,2000})\\+)?({user}[^\\\s]{1,2000})""",
  ]
}
```