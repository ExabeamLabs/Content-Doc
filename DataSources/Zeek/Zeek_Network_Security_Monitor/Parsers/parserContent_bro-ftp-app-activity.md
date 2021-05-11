#### Parser Content
```Java
{
Name = bro-ftp-app-activity
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch_sec"
  Conditions = [ """<Bro FTP App Activity Conditions>""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """.*?({time}\d{1,100})\.\d{6}""",
    """([^\t]+\t){2}(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\t]+))\t({src_port}\d{1,100})""",
    """([^\t]+\t){4}(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\t]+))\t({dest_port}\d{1,100})""",
    """\t21\t(?:<unknown>|({user}[^\t]+))""",
    """\t21\t([^\t]+\t){2}({activity}[^\t]+)""",
    """({app}ftp)""",
    """\t21\t([^\t]+\t){3}ftp:(\/)+.*?\/({object}[^\/\t]+)\t(?:-|<unknown>|({mime}[^\s]+))""",
    """\t21\t([^\t]+\t){7}(?:-|({additional_info}[^\(\t]+))"""
  ]
}
```