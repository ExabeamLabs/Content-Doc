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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """.*?({time}\d{1,100})\.\d{6}""",
    """([^\t]{1,2000}\t){2}(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\t]{1,2000}))\t({src_port}\d{1,100})""",
    """([^\t]{1,2000}\t){4}(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\t]{1,2000}))\t({dest_port}\d{1,100})""",
    """\t21\t(?:<unknown>|({user}[^\t]{1,2000}))""",
    """\t21\t([^\t]{1,2000}\t){2}({activity}[^\t]{1,2000})""",
    """({app}ftp)""",
    """\t21\t([^\t]{1,2000}\t){3}ftp:(\/)+.*?\/({object}[^\/\t]{1,2000})\t(?:-|<unknown>|({mime}[^\s]{1,2000}))""",
    """\t21\t([^\t]{1,2000}\t){7}(?:-|({additional_info}[^\(\t]{1,2000}))"""
  ]
}
```