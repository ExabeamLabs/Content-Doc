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
    """exabeam_host=({host}[\w.\-]+)""",
    """.*?({time}\d+)\.\d{6}""",
    """(?:[^\t]+\t){11}.*?<({sender}[^\t>]+)""",
    """(?:[^\t]+\t){12}.*?<({user}[^>\t"]+)""",
    """(?:[^\t]+\t){12}({recipients}[^\t]+)""",
    """(?:[^\t]+\t){16}({subject}[^\t]+)""",
    """\tfrom .*?\(.*?(\[)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\])?\)""",
    """(?=\tfrom.+?\tfrom)\tfrom.+?\tfrom .*?\(.*?(\[)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\])?\)"""
    """({alert_name}bro_smtp)""",
  ]
  DupFields = [ "alert_name->alert_type", "user->orig_user", "sender->external_address" ]
}
```