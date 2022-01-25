#### Parser Content
```Java
{
Name = s-bro-email-in
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """bro_smtp""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """.*?({time}\d{1,100})\.\d{6}""",
    """(?:[^\t]{1,2000}\t){11}.*?<({sender}[^\t>]{1,2000})""",
    """(?:[^\t]{1,2000}\t){12}.*?<({user}[^>\t"]{1,2000})""",
    """(?:[^\t]{1,2000}\t){12}({recipients}[^\t]{1,2000})""",
    """(?:[^\t]{1,2000}\t){16}({subject}[^\t]{1,2000})""",
    """\tfrom .*?\(.*?(\[)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\])?\)""",
    """(?=\tfrom.+?\tfrom)\tfrom.+?\tfrom .*?\(.*?(\[)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\])?\)"""
    """({alert_name}bro_smtp)""",
  ]
  DupFields = [ "alert_name->alert_type", "user->orig_user", "sender->external_address" ]
}
```